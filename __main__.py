import functools, itertools, types, builtins, operator, six
import argparse, json, math, os, os.path, codecs, heapq
from peepdf import *

PDFCodec = codecs.lookup('iso8859-1')

def ParsePDF(infile):
    P = PDFCore.PDFParser()
    _, p = P.parse(infile, forceMode=True, looseMode=True, manualAnalysis=True)
    end = reduce(lambda agg, item: agg + [len(item) + (agg[-1] if len(agg) else 0)], P.fileParts, [])
    bounds = [(right - len(content), right) for right, content in zip(end, P.fileParts)]
    return p, bounds

def WritePDF(outfile, comments):

    offset = 0
    comment_fmt = functools.partial("%{:s}{newline:s}".format, newline=os.linesep)
    with open(outfile, 'wb') as out:

        # Start out by writing any comments that we were given
        for comment in comments:
            data = comment_fmt(comment)
            out.write(data)
            offset += len(data)

        # Our main loop that writes to our file
        try:
            while True:
                item = (yield offset)
                data = b"{:s}{newline:s}".format(item.toFile().rstrip(), newline=os.linesep)
                out.write(data)
                offset += len(data)

        except GeneratorExit: pass
    return

FormatStream = "{:d} {:d} obj".format

def DecodeFromPDF(element):
    if isinstance(element, PDFCore.PDFNum):
        res = element.getValue()
        return float(res) if '.' in res else int(res)
    elif isinstance(element, PDFCore.PDFName):
        res = element.getValue()
        return "{:s}".format(res)
    elif isinstance(element, PDFCore.PDFString):
        res = element.getValue()
        return str(res)
    elif isinstance(element, PDFCore.PDFHexString):
        res = element.getValue()
        return "<{:s}>".format(res.encode('hex'))
    elif isinstance(element, PDFCore.PDFReference):
        res = element.getValue()
        return str(res)
    elif isinstance(element, PDFCore.PDFArray):
        iterable = element.getElements()
        return [ DecodeFromPDF(item) for item in iterable ]
    elif isinstance(element, PDFCore.PDFDictionary):
        iterable = element.getElements()
        return { str(name) : DecodeFromPDF(item) for name, item in iterable.items() }
    elif isinstance(element, PDFCore.PDFBool):
        return bool(element)
    raise TypeError(element)

def EncodeToPDF(instance):
    if isinstance(instance, PDFCore.PDFObject):
        return instance
    elif isinstance(instance, dict):
        # ensure the names in the dictionary are proper strings...
        decoded = { name if isinstance(name, unicode) else PDFCodec.decode(name, 'ignore')[0] : item for name, item in instance.items() }
        res = { PDFCodec.encode(name, 'ignore')[0] : EncodeToPDF(item) for name, item in decoded.items() }
        return PDFCore.PDFDictionary(elements=res)

    elif isinstance(instance, list):
        res = [ EncodeToPDF(item) for item in instance ]
        return PDFCore.PDFArray(elements=res)

    elif isinstance(instance, float):
        return PDFCore.PDFNum("{:f}".format(instance))

    elif isinstance(instance, bool):
        return PDFCore.PDFBool("{!s}".format(instance).lower())

    elif isinstance(instance, six.integer_types):
        return PDFCore.PDFNum("{:d}".format(instance))

    elif isinstance(instance, six.string_types):
        res, _ = PDFCodec.encode(instance, 'ignore') if isinstance(instance, unicode) else (instance, len(instance))

        # check if it's a name
        if res.startswith(b'/'):
            return PDFCore.PDFName(res)

        # check if it's a reference
        try:
            if len(res.split(b' ')) == 3:
                index, generation, reference = res.split(b' ', 3)

                int(index)
                assert int(generation) == 0
                assert reference == b'R'
                return PDFCore.PDFReference(index, generation)

        except (AssertionError, ValueError):
            pass

        # check if it's a hexstring
        try:
            left, middle, right = res[:1], res[1:-1], res[-1:]
            if (left, right) == ('<', '>') and len(middle) % 2 == 0 and middle.lower() == middle and middle.translate(None, b' \t\n') == middle:
                return PDFCore.PDFHexString(middle)

        except TypeError:
            pass

        # forget it, it's a string
        return PDFCore.PDFString(res)
    raise TypeError(instance)

def do_listpdf(infile, parameters):
    P, _ = ParsePDF(infile)
    stats = P.getStats()

    print("Parsed file: {:s}".format(infile))
    if P.binary:
        print("BinaryChars: {:s}".format(P.binaryChars.encode('hex')))
    print("Version: {:.1f}".format(float(stats['Version'])))
    print("Total size: {size:+#x} ({size:d})".format(size=int(stats['Size'])))
    print("MD5: {:s}".format(stats['MD5']))
    print("SHA1: {:s}".format(stats['SHA1']))
    print("SHA256: {:s}".format(stats['SHA256']))
    print('')

    for i, position in enumerate(P.getOffsets()):
        if operator.contains(position, 'header'):
            offset, _ = position['header']
            print("Header: {:#x}".format(offset))

        offset, size = position['trailer']
        print("\tTrailer[{:d}]: {:#x}{:+x}".format(i, offset, size))
        offset, _ = position['eof']
        print("\t%%EOF[{:d}]: {:#x}".format(i, offset))
        print('')

    for i, V in enumerate(stats['Versions']):
        print("Information for Trailer {:d}".format(i))
        count, items = V['Streams']
        print("\tNumber of streams: {:d}".format(int(stats['Streams'])))
        print("\tIndices of streams: {:s}".format(', '.join(map("{:d}".format, items))))
        count, item = V['Encoded']
        print("\tIndices of encoded streams: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))

        if V['Decoding Errors']:
            count, item = V['Decoding Errors']
            print("\tStreams with decoding errors: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
        print('')

        count, items = V['Xref Streams']
        print("\tNumber of xref streams: {:d}".format(int(count)))
        print("\tIndices of xref streams: {:s}".format(', '.join(map("{:d}".format, items))))
        print('')

        if V['Object Streams']:
            count, items = V['Object Streams']
            print("\tNumber of object streams: {:d}".format(int(count)))
            print("\tIndices of object streams: {:s}".format(', '.join(map("{:d}".format, items))))

        if V['Errors']:
            count, item = V['Errors']
            print("\tObjects with errors: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
        print('')

        count, items = V['Objects']
        print("\tTotal number of objects: {:d}".format(int(stats['Objects'])))
        print("\tIndices of objects: {:s}".format(', '.join(map("{:d}".format, items))))

        if V['Compressed Objects']:
            _, items = V['Compressed Objects']
            print("\tIndices of compressed objects: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
        print('')

    for i, position in enumerate(P.getOffsets()):
        max_digits = map(max, zip(*position['objects']))
        bases = [ 10, 0x10, 0x10 ]
        digits_id, digits_pos, digits_sz = (math.trunc(math.ceil(math.log(item, base))) for item, base in zip(max_digits, bases))

        print("Object positions for trailer {:d}:".format(i))
        for id, offset, size in position['objects']:
            object = P.getObject(id)
            meta = object.getStats()
            dictionary = object.getElements()
            if isinstance(dictionary, dict):
                items = [ "{:s}={!s}".format(name, item.getRawValue()) for name, item in sorted(dictionary.items())]
            else:
                items = [ item.getRawValue() for item in dictionary ]
            description = ', '.join(items).translate(None, '\r\n')
            print("\t [{offset:#0{digits_pos:d}x}{size:+0{digits_sz:d}x}] {:d} {:d} obj {padding:s}: {dict!s}".format(id, 0, offset=offset, size=size, dict=description if len(description) < 132 else description[:132] + '...', digits_pos=2+digits_pos, digits_sz=1 + digits_sz, padding=' '*(digits_id - len("{:d}".format(id)))))
        print('\n')
        continue

    return 0

def read_revision(pdf, revision, bounds):
    stats, objects = pdf.getStats(), pdf.body[revision].objects

    result = {}
    for index in sorted(objects):
        iobject, object = objects[index], objects[index].object
        if object.getType() != 'stream':
            continue
        res = pdf.getObject(index, version=revision)
        result[iobject.getOffset()] = (revision, index, res, iobject.getSize())
        #print revision, index, hex(iobject.offset), hex(iobject.getOffset()), hex(iobject.getSize()), object.getType()

    # add our xref table entries
    for item in pdf.crossRefTable[revision]:
        if item:
            result[item.getOffset()] = (revision, None, item, item.getSize())
        continue

    # add our trailer entries
    for item in pdf.trailer[revision]:
        if item:
            result[item.getOffset()] = (revision, None, item, item.getSize())
        continue
    return result

def find_trailermeta(trailer):
    stream, section = trailer
    if section is not None:
        selected = section if len(section.getTrailerDictionary().getElements()) else stream
    else:
        selected = stream

    # Give XRefStm priority if that's what's in the trailer dictionary
    meta = selected.getTrailerDictionary()
    elements = meta.getElements()
    return int(elements[b'XRefStm'].getValue()) if operator.contains(elements, b'XRefStm') else selected.getLastCrossRefSection(), meta, selected

def find_previous_offset(offset, list):
    if len(list) == 1:
        return list[0]

    # divide-and-conquer to find the object that an offset is pointing into
    center = len(list) // 2
    if offset > list[center]:
        return find_previous_offset(offset, list[center:])
    return find_previous_offset(offset, list[:center])

def get_xrefs(trailer, table):
    offset, _, object = find_trailermeta(trailer)
    if not operator.contains(table, offset):
        return

    while True:

        # If we can't find the offset in our table, then seek backwards until
        # we find one that matches.
        if not operator.contains(table, offset):
            offset = find_previous_offset(offset, sorted(table))
        revision, _, object, size = table[offset]

        # Ensure that it's of a valid type.
        if not isinstance(object, (PDFCore.PDFTrailer, PDFCore.PDFStream, PDFCore.PDFCrossRefSection)):
            print("Warning: Offset ({:#x}) from trailer points to object of type {!s}".format(offset, object.__class__))
            break

        # If we're pointing at another PDFTrailer, then check if there's an
        # XRefStm to move onto...if not, then this contains our xref table
        # in its stream.
        if isinstance(object, PDFCore.PDFTrailer):
            meta = object.getTrailerDictionary()
            elements = meta.getElements()
            if operator.contains(elements, b'/XRefStm'):
                offset = int(elements[b'XRefStm'].getValue())
                continue
            offset = object.getLastCrossRefSection()
            continue

        yield object

        # If we found a stream, then we can keep going
        if isinstance(object, PDFCore.PDFStream):
            elements = object.getElements()

        # Getting to a crossrefsection means that we're done here
        elif isinstance(object, PDFCore.PDFCrossRefSection):
            return

        else:
            raise ValueError(object)

        # If our elements aren't a dictionary, or there's no offset
        # to continue from, then just leave. This might be badly
        # formatted anyways
        if not isinstance(elements, dict) or not operator.contains(elements, b'/Prev'):
            break

        # Use the offset to find the next table
        previous = elements[b'/Prev']
        if not isinstance(previous, PDFCore.PDFNum):
            raise TypeError(previous)
        offset = int(previous.getValue())
    return

def collect_objects(pdf, revision, path, parameters):
    stats = pdf.getStats()

    objects = {}
    _, items = stats['Versions'][revision]['Objects']
    for index in items:
        object = pdf.getObject(index, version=revision)
        objects[index] = object

    return objects

def dump_stream(objects, object, path_fmt, compressed=False):
    meta = object.getElements()

    # Figure out whether there were any parsing errors, because
    # if there was..then we just dump the stream as-is.
    if object.filter in {None} or compressed or len(object.errors):
        suffix = 'Binary'

        # First grab the length out of the stream's dictionary
        length = meta[b'/Length']
        if isinstance(length, PDFCore.PDFNum):
            size = int(length.getValue())

        # Sometimes it can be a reference...grrr
        elif isinstance(length, PDFCore.PDFReference):
            indirect = objects[length.getId()]
            direct = indirect.object
            size = int(direct.getValue())

        else:
            raise TypeError(length)

        # Fix up the actual stream length by removing the trailing newlines
        # because peepdf doesn't know how to fucking parse object streams
        # properly
        data = object.getRawStream()[:size]

    # Otherwise, we can decode to stream and write it to our path
    elif isinstance(object.filter, PDFCore.PDFName):
        filter = object.filter.getValue()
        suffix = filter.translate(None, '/')

        data = object.getStream()

    elif isinstance(object.filter, PDFCore.PDFArray):
        filters = [ item.getValue() for item in object.filter.getElements() ]
        suffix = ','.join(item.translate(None, '/') for item in filters) + ('' if len(filters) > 1 else ',')

        data = object.getStream()

    else:
        raise TypeError(object.filter)

    with open(path_fmt(ext=suffix), 'wb') as out:
        out.write(data)
    return len(data)

def dump_objects(pdf, revision, path, compressed=False):
    stats = pdf.getStats()

    result = []
    _, items = stats['Versions'][revision]['Objects']
    for index in items:
        object = pdf.getObject(index, version=revision)

        Fobjectname = "{:d}_0_obj".format
        Fdump = functools.partial(json.dump, encoding=PDFCodec.name, indent=4, sort_keys=True)
        Ftypename = lambda element: element.__class__.__name__

        # If there were any errors, then notify the user.
        if len(object.errors):
            print("Errors in revision {:d} ({:s}) with {:s}: {:d}".format(revision, path, Fobjectname(index), len(object.errors)))

        # Otherwise, aggregate the object index into our success list
        else:
            result.append(index)

        # This object is a stream, and so we'll need to dump its
        # contents into a file.
        if isinstance(object, PDFCore.PDFStream):
            stream_fmt = functools.partial("{:s}.{ext:s}".format, os.path.join(path, Fobjectname(index)))
            dump_stream(pdf.body[revision].objects, object, stream_fmt, compressed)

        # Each object should have a dictionary or a list, so encode it
        # into json, so we can dump it to a file
        elements = DecodeFromPDF(object)

        elements_name = '.'.join([Fobjectname(index), 'json'])
        Fdump(elements, open(os.path.join(path, elements_name), 'wt'))
    return result

def dump_trailer(pdf, revision, path):
    Fdump = functools.partial(json.dump, encoding=PDFCodec.name, indent=4, sort_keys=True)

    # Grab our trailer dictionary, and encode it.
    _, meta, _ = find_trailermeta(pdf.trailer[revision])
    elements = DecodeFromPDF(meta)

    # Now just to write this thing somewhere...
    elements_name = '.'.join(['trailer', 'json'])
    Fdump(elements, open(os.path.join(path, elements_name), 'wt'))
    return True

def dump_xrefs(pdf, revision, table, path):
    Fdump = functools.partial(json.dump, encoding=PDFCodec.name, indent=4, sort_keys=True)

    # Iterate through all of our xrefs that we snagged, and start
    # writing them to disk..
    iterable = get_xrefs(pdf.trailer[revision], table)
    for index, xref in enumerate(iterable):
        Fxrefname = "xref_{:d}".format
        name_fmt = functools.partial("{:s}.{ext:s}".format, os.path.join(path, Fxrefname(index)))

        # If it's a stream, then write it uncompressed to our file
        if isinstance(xref, PDFCore.PDFStream):
            dump_stream(pdf.body[revision].objects, xref, name_fmt, compressed=False)

            elements = DecodeFromPDF(xref)
            elements_name = name_fmt(ext='json')
            Fdump(elements, open(elements_name, 'wt'))
            continue

        # Otherwise, we need to trust peepdf's .toFile() method
        with open(name_fmt(ext='Binary'), 'wb') as out:
            out.write(xref.toFile())
        continue
    return

def do_readpdf(infile, parameters):
    P, bounds = ParsePDF(infile)
    position = P.getOffsets()
    stats = P.getStats()

    if len(stats['Versions']) != len(parameters.directory):
        count = len(stats['Versions'])
        print("The input document that was specified ({:s}) contains {:d} individual trailers!".format(infile, count))
        print('')
        print("Please provide {:d} paths to extract each trailer into in order to continue!".format(count))
        print('')
        raise ValueError("Only {:d} directories were provided...".format(len(parameters.directory)))

    # Go through every single revision and extract the boundaries of all our
    # objects into a table. This way we can use it to find any version of an
    # object parsed by peepdf. This seems to be the best way to deal with all
    # of these weirdly formatted PDFs and still remain compatible with the
    # way the author of peepdf wrote his tool.

    table, iterable = {}, [ read_revision(P, version, bounds[version]) for version in range(len(P.body)) ]
    [ table.update(item) for item in iterable ]

    # Now we should have all of our streams, and we should be able to figure out
    # the correct trailer for a particular revision.
    for version in range(len(P.body)):
        stream, section = P.trailer[version]
        offset = stream.getLastCrossRefSection()
        if not operator.contains(table, offset):
            print("Unable to locate stream for trailer {:d} at offset {:+#x}".format(version, offset))
            continue
        continue

    # Now we can iterate through all the objects in a given revision,
    # and write them into the directory provided by the user.
    for version in range(len(P.body)):
        path = parameters.directory[version]
        if not os.path.isdir(path):
            print("Skipping revision {:d} due to output path not being a directory: {:s}".format(version, path))

        else:
            dump_objects(P, version, path, compressed=parameters.compressed)
            dump_trailer(P, version, path)
            dump_xrefs(P, version, table, path)
        continue
    return 0

def object_size(object, index, generation=0):
    if generation:
        raise ValueError("peepdf does not support objects w/ a non-zero generation")

    # we need to calculate this ourselves because peepdf doesn't expose this
    # to us in any form. the author instead hardcodes this calculation
    fmt = functools.partial('{:d} {:d} obj{newline:s}{!s}{newline:s}endobj{newline:s}'.format, newline=os.linesep)
    return len(fmt(index, generation, object.getRawValue()))

def collect_files(paths):
    result, xrefs, trailers = {}, {}, []
    for item in paths:
        if not os.path.isfile(item):
            print("Skipping non-file path: {:s}".format(item))
            continue
        fullname = os.path.basename(item)
        name, ext = os.path.splitext(fullname)

        # validate our name format
        components = name.split('_')
        if not operator.contains({1, 2, 3}, len(components)):
            print("Skipping path due to invalid format: {:s}".format(item))
            continue

        # check if it's the trailer
        if len(components) == 1:
            trailer, = components
            if trailer == 'trailer':
                trailers.append(item)
            else:
                print("Skipping path due to invalid trailer filename: {:s}".format(item))
            continue

        # check if it's an xref table
        if len(components) == 2:
            xref, index = components
            if xref == 'xref':
                try:
                    int(index)

                except ValueError:
                    pass

                else:
                    xrefs.setdefault(int(index), []).append(item)
                    continue

            print("Skipping path due to invalid xref filename: {:s}".format(item))
            continue

        # validate its components
        index, generation, object = components
        if generation != '0' and object != 'obj':
            print("Skipping path due to invalid format: {:s}".format(item))
            continue

        try:
            int(index)
        except ValueError:
            print("Skipping path due to invalid index: {:s}".format(item))

        result.setdefault(int(index), []).append(item)
    return result, trailers, xrefs

def pairup_files(input):
    result = {}

    for index, files in input.items():

        # pair up our files
        meta, content = [], []
        for item in files:
            fullname = os.path.basename(item)
            name, ext = os.path.splitext(fullname)
            if name != "{:d}_0_obj".format(index):
                print("Skipping path for object {:d} due to invalid name: {:s}".format(index, item))
                continue
            if ext == '.json':
                meta.append(item)
            else:
                content.append(item)
            continue

        # if no metafile was found, then skip this object
        if len(meta) == 0:
            print("Skipping object {:d} as no metafile was found: {!r}".format(index, meta))
            continue

        # warn the user if they provided more than one file for a single object
        if len(meta) > 1:
            print("More than one metafile was specified for object {:d}: {!r}".format(index, meta))

        if len(content) > 1:
            print("More than one file was specified for object {:d}: {!r}".format(index, content))

        result[index] = (meta[0], content[0] if len(content) > 0 else None)

    return result

def pairup_xrefs(input):
    result = {}

    Ftrailername = "xref_{:d}".format
    for index, files in input.items():

        # pair up our files
        meta, xrefs = [], []
        for item in files:
            fullname = os.path.basename(item)
            name, ext = os.path.splitext(fullname)
            if name != Ftrailername(index):
                print("Skipping path for trailer {:d} due to invalid name: {:s}".format(index, item))
                continue

            if ext == '.json':
                meta.append(item)
            else:
                xrefs.append(item)
            continue

        # if no metafile was found, then skip this object
        if len(xrefs) == 0:
            print("Skipping xref {:d} as no table was found: {!r}".format(index, xrefs))
            continue

        # warn the user if they provided more than one file for a single object
        if len(meta) > 1:
            print("More than one metafile was specified for xref {:d}: {!r}".format(index, meta))

        if len(xrefs) > 1:
            print("More than one table was specified for xref {:d}: {!r}".format(index, xrefs))

        result[index] = (meta[0] if len(meta) else None, xrefs[0])
    return result

def load_stream(infile, meta=None):
    _, res = os.path.splitext(infile)
    _, filter = res.split('.', 1)

    data = open(infile, 'rb').read()

    # If there's no mta dictionary, then don't bother creating it.
    if meta is None:
        stream = PDFCore.PDFObjectStream()

    # The author of peepdf seems to smoke crack, so we'll explicitly
    # modify the fields to get his shit to work...
    else:
        stream = PDFCore.PDFObjectStream(rawDict=meta.getRawValue())
        stream.elements = meta.getElements()

    # If the suffix is ".Binary", then this is just a raw file with
    # no filter attached.
    if filter.lower() == u'binary':
        stream.decodedStream = data
        return None, stream

    # If there's a ',' in the suffix, then this is an array. Split
    # across the ',' and make a PDFArray filter.
    if operator.contains(filter, ','):
        filters = filter.split(',')
        elements = [ PDFCore.PDFName("/{:s}".format(filter)) for filter in filters if filter]
        stream.filter = PDFCore.PDFArray(elements=elements)

    # Otherwise, it's just a straight-up PDFName
    else:
        stream.filter = PDFCore.PDFName("/{:s}".format(filter))

    # Our stream is encoded, so set the correct fields explicitly, and
    # ask peepdf to encode it for us.
    stream.isEncodedStream = True
    stream.decodedStream = data
    wtf, you = stream.encode()
    if wtf:
        raise NotImplementedError(you)
    return stream.filter, stream

def load_body(pairs):
    body = {}
    for index, (metafile, contentfile) in pairs.items():
        meta = json.load(open(metafile, 'rt')) or {}

        if contentfile:
            try:
                filter_and_stream = load_stream(contentfile, EncodeToPDF(meta))

            except NotImplementedError as E:
                print("Unable to load content (\"{:s}\") for object {:d}".format(contentfile, index))
                raise E
            body[index] = filter_and_stream

        else:
            body[index] = None, EncodeToPDF(meta)
        continue
    return body

def load_xrefs(pairs):
    result = {}
    for index in sorted(pairs):
        metafile, xfilename = pairs[index]

        # If there's no metafile, then no need to do anything here
        if metafile is None:
            meta = None

        # Load any metadata that was specified
        else:
            metadict = json.load(open(metafile, 'rt'))
            meta = None if metadict is None else EncodeToPDF(metadict)

        # Read our file and remember its filter type...Never forget.
        try:
            filter_and_stream = load_stream(xfilename, None if meta is None else EncodeToPDF(meta))

        except NotImplementedError as E:
            print("Unable to load content (\"{:s}\") for xref {:d}".format(contentfile, index))
            raise E
        result[index] = filter_and_stream
    return result

def load_trailer(infile):
    metadict = json.load(open(infile, 'rt'))
    meta = EncodeToPDF(metadict)
    if meta.hasElement('/Size'):
        return PDFCore.PDFTrailer(meta)

    # If no size was specified, then temporarily create it so that
    # we can construct a PDFTrailer with PeePDF
    size = PDFCore.PDFNum("{:d}".format(0))
    meta.setElement('/Size', size, update=False)

    # Hand-off our PDFDict to PeePDF
    res = PDFCore.PDFTrailer(meta)

    # Now PeePDF won't bitch, so we can remove it and continue onwards
    res.dict.delElement('/Size', update=False)
    return res

def filters_okay(filter, meta):
    if not operator.contains(meta, u'/Filter'):
        return filter is None

    # If we don't know what the type is, then we'll try to use .getValue()
    # to do our equivalency test...
    if filter and not all(isinstance(item, (PDFCore.PDFArray, PDFCore.PDFName)) for item in [filter, meta[u'/Filter']]):
        return filter.getValue() == meta[u'/Filter'].getValue() if isinstance(filter, PDFCore.PDFObject) else False

    # We need to check that the encoding will result in the same value, however
    # some of these can be a PDFName. To hack around this, we'll just convert
    # both to a PDFArray so we can compare them consistently.
    res = meta[u'/Filter']
    mfilter = PDFCore.PDFArray(elements=[res]) if isinstance(res, PDFCore.PDFName) else res
    ufilter = PDFCore.PDFArray(elements=[filter]) if isinstance(filter, PDFCore.PDFName) else PDFCore.PDFArray(elements=[]) if filter is None else filter

    # Verify that the lengths match because Python3 doesn't have an zip_longest
    if len(ufilter.getElements()) != len(mfilter.getElements()):
        return False

    # Now we need to walk through both arrays and see if they actually match
    for uitem, mitem in zip(ufilter.getElements(), mfilter.getElements()):
        if not all(isinstance(item, PDFCore.PDFName) for item in [uitem, mitem]):
            return False

        # Now that we know that we got two names, we can simply compare their values
        uname, mname = (item.getValue() for item in [uitem, mitem])
        if uname != mname:
            return False
        continue
    return True

def update_body(objects, remove_metadata=False):

    # Update the objects dict in-place
    for index in sorted(objects):
        flt, obj = objects[index]
        stats = obj.getStats()

        Fobject = lambda object, index: u"{:s} object {:d}".format(object.getType(), index)
        Ffieldvalue = lambda field: u"{:s}({!r})".format(field.__class__.__name__, field.getValue())
        Ffieldname = lambda name: u"`/{:s}`".format(name)

        # Ensure that we're an object stream
        if not isinstance(obj, PDFCore.PDFObjectStream):
            continue
        meta, is_empty = obj.getElements(), not (obj.rawValue and True or False)

        # And that our metadata is a dict that we can update
        res = EncodeToPDF(meta)
        if not isinstance(res, PDFCore.PDFDictionary):
            t = res.__class__
            print("Skipping {:s} while updating body due to invalid metadata type ({!s})".format(Fobject(obj, index), t.__name__))
            continue

        meta_update = {}

        # First check if we need update the /Length for the stream
        size = len(obj.encodedStream if obj.isEncoded() else obj.decodedStream)
        if is_empty and not operator.contains(meta, u'/Length'):
            print("{:s} is empty and does not have a {:s} field...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length')))

        elif not operator.contains(meta, u'/Length'):
            meta_update[u'/Length'] = PDFCore.PDFNum(u"{:d}".format(size))

        elif not isinstance(meta[u'/Length'], PDFCore.PDFNum):
            t = PDFCore.PDFNum
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length'), Ffieldvalue(meta[u'/Length']), t.__name__))

        elif int(meta[u'/Length'].getValue()) != size:
            meta_update[u'/Length'] = PDFCore.PDFNum(u"{:d}".format(size))

        # Instead of updating the filter, we're going to simply check it and
        # see if they correspond. This way the user can do the proper thing,
        # and update the metadata when they change the encoding.
        if not filters_okay(flt, meta):
            if operator.contains(meta, u'/Filter'):
                print("{:s} has a {:s} of value {:s} which does not correspond to the file encoding: {:s}.".format(Fobject(obj, index).capitalize(), Ffieldname('Filter'), Ffieldvalue(meta[u'/Filter']), flt and Ffieldvalue(flt) or 'none'))
            else:
                print("{:s} is missing the {:s} field. This does not correspond to the file encoding: {:s}.".format(Fobject(obj, index).capitalize(), Ffieldname('Filter'), flt and Ffieldvalue(flt) or 'none'))
            print("    If this was unintentional, please update its metadata!")

        # Check if anything needs to be updated and then do it
        if meta_update:
            old = ' '.join('='.join([name.split('/',1)[1], '<Removed>' if operator.contains(meta, name) and meta[name] is None else Ffieldvalue(meta[name]) if operator.contains(meta, name) else '<Missing>']) for name in meta_update)
            new = ' '.join('='.join([name.split('/',1)[1], '<Removed>' if item is None else Ffieldvalue(item)]) for name, item in meta_update.items())
            print("Updating the fields for {:s} from {!s}: {!s}".format(Fobject(obj, index), old, new))

            remove = { name for name, item in meta_update.items() if item is None }
            update = { PDFCodec.encode(name)[0] : meta_update[name] for name in meta_update if name not in remove }
            meta.update(update)
            [ meta.pop(PDFCodec.encode(name)[0]) for name in remove ]

        # Re-assign our metadata the stream directly because peepdf sucks
        obj.rawValue = PDFCore.PDFDictionary(elements=meta).getRawValue()
        obj.elements = meta

    # That's it, we've updated the metadata for each object
    return objects

def update_xrefs(objects, offset, remove_metadata=False):

    # Update the xrefs in-place
    for index in sorted(objects):
        flt, obj = objects[index]
        stats = obj.getStats()

        Fxref = lambda object, index: u"{:s} xref {:d}".format(object.getType(), index)
        Ffieldvalue = lambda field: u"{:s}({!r})".format(field.__class__.__name__, field.getValue())
        Ffieldname = lambda name: u"`/{:s}`".format(name)

        # Ensure that we're an object stream
        if not isinstance(obj, PDFCore.PDFObjectStream):
            print("Skipping {:s} while updating xrefs...".format(Fxref(obj, index)))
            continue
        meta, is_empty = obj.getElements(), not (obj.rawValue and True or False)

        # And that our metadata is a dict that we can update
        res = EncodeToPDF(meta)
        if not isinstance(res, PDFCore.PDFDictionary):
            t = res.__class__
            print("Skipping {:s} while updating xrefs due to invalid metadata type ({!s})".format(Fxref(obj, index), t.__name__))
            continue

        meta_update = {}

        # First check and update the length so it corresponds to the stream
        size = len(obj.getRawStream())
        if is_empty and not operator.contains(meta, u'/Length'):
            print("{:s} is empty and does not have a {:s} field...skipping its update!".format(Fxref(obj, index).capitalize(), Ffieldname('Length')))

        elif not operator.contains(meta, u'/Length'):
            meta_update[u'/Length'] = PDFCore.PDFNum(u"{:d}".format(size))

        elif not isinstance(meta[u'/Length'], PDFCore.PDFNum):
            t = PDFCore.PDFNum
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fxref(obj, index).capitalize(), Ffieldname('Length'), Ffieldvalue(meta['/Length']), t.__name__))

        elif int(meta[u'/Length'].getValue()) != size:
            meta_update[u'/Length'] = PDFCore.PDFNum(u"{:d}".format(size))

        # Now check to see if the /Filter needs to be fixed
        if flt is None and not operator.contains(meta, u'/Filter'):
            pass

        elif not operator.contains(meta, u'/Filter'):
            print("{:s} does not have a {:s} field...skipping its update!".format(Fxref(obj, index).capitalize(), Ffieldname('Filter')))

        elif flt and not operator.contains(meta, u'/Filter'):
            meta_update[u'/Filter'] = flt

        elif not isinstance(meta[u'/Filter'], (PDFCore.PDFName, PDFCore.PDFArray)):
            t = PDFCore.PDFName
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fxref(obj, index).capitalize(), Ffieldname('Filter'), Ffieldvalue(meta['/Filter']), t.__name__))

        elif flt is None and remove_metadata:
            meta_update[u'/Filter'] = None

        elif flt and meta[u'/Filter'].getValue() != flt.getValue():
            meta_update[u'/Filter'] = flt

        # Check if anything needs to be updated and then do it
        if meta_update:
            old = ' '.join('='.join([name.split('/',1)[1], '<Removed>' if operator.contains(meta, name) and meta[name] is None else Ffieldvalue(meta[name]) if operator.contains(meta, name) else '<Missing>']) for name in meta_update)
            new = ' '.join('='.join([name.split('/',1)[1], '<Removed>' if item is None else Ffieldvalue(item)]) for name, item in meta_update.items())
            print("Updating the fields for {:s} from {!s}: {!s}".format(Fxref(obj, index), old, new))

            remove = { name for name, item in meta_update.items() if item is None }
            update = { PDFCodec.encode(name)[0] : meta_update[name] for name in meta_update if name not in remove }
            meta.update(update)
            [ meta.pop(PDFCodec.encode(name)[0]) for name in remove ]

        # Re-assign our metadata the stream directly because peepdf sucks
        obj.rawValue = PDFCore.PDFDictionary(elements=meta).getRawValue() if meta else b''
        obj.elements = meta or {}

    # Go back through the objects and repair the offsets
    indices = sorted(objects)
    for ci, ni in zip(indices[:-1], indices[1:]):
        _, co = objects[ci]
        _, no = objects[ni]

        meta = no.getElements()
        meta[b'/Prev'] = PDFCore.PDFNum(str(offset))
        no.rawValue = PDFCore.PDFDictionary(elements=meta).getRawValue()
        no.elements = meta

        offset += object_size(co, index)
    return objects

def find_xrefs(objects):
    result = []
    for index in sorted(objects):
        _, obj = objects[index]
        if not isinstance(obj, (PDFCore.PDFObjectStream, PDFCore.PDFDictionary)):
            continue

        # Check to see if this has a /Type in it
        meta = obj.getElements()
        if not operator.contains(meta, b'/Type'):
            continue

        # Check if it's an XRef
        if meta['/Type'].getValue() != b'/XRef':
            continue

        result.append(index)
    return result

def calculate_xrefs(objects, base=0, offset=0):
    if not objects:
        return []

    bounds = 0, max(sorted(objects))

    # first build a slot table so we can figure out which objects
    # will be free versus in-use
    slots = []
    for index in range(*bounds):
        slots.append(True if index in objects else False)
    slots.append(False)

    # now we can iterate through our objects figuring out which slots
    # to update with either an object offset or a free index
    result = []
    for index in range(*bounds):
        if index not in objects:
            next = slots[1 + index:].index(False)
            xref = PDFCore.PDFCrossRefEntry(1 + index + next, 0xffff, 'f')
            result.append(xref)
            continue

        # if our object exists, then create an xref entry for it
        _, obj = objects[index]
        xref = PDFCore.PDFCrossRefEntry(offset, 0, 'n')
        result.append(xref)
        offset += object_size(obj, base + index)
    return result + [PDFCore.PDFCrossRefEntry(offset, 0, 'n')]

def do_writepdf(outfile, parameters):

    # first collect all of our object names
    object_files, trailer_files, xref_files = collect_files(parameters.files)
    object_pairs = pairup_files(object_files)
    xref_pairs = pairup_xrefs(xref_files)

    # setup our header
    HEADER = []
    HEADER.append("PDF-{:.1f}".format(parameters.set_version))
    HEADER.append(parameters.set_binary if parameters.set_binary else '')

    # create our pdf instance
    P = WritePDF(outfile, HEADER)
    offset = next(P)

    # Load our pdf body and update it if necessary
    objects = load_body(object_pairs)

    if not len(objects):
        raise ValueError("No valid objects could be loaded from the files that were provided as parameters: {:s}".format(', '.join(parameters.files)))

    if parameters.update_metadata or parameters.remove_metadata:
        objects = update_body(objects, remove_metadata=parameters.remove_metadata)
    xrefs_body = calculate_xrefs(objects, 0, offset)

    # Now to build this thing...
    body = PDFCore.PDFBody()
    body.setNextOffset(offset)
    for index in sorted(objects):
        _, obj = objects[index]
        if xrefs_body[index].objectOffset != body.getNextOffset():
            raise AssertionError((body.getNextOffset(), xrefs_body[index].objectOffset))
        body.setObject(id=index, object=obj)

    # Load the xrefs that were provided by the user
    xrefs = load_xrefs(xref_pairs)
    if parameters.update_xrefs or parameters.remove_metadata:
        xrefs = update_xrefs(xrefs, offset=body.getNextOffset(), remove_metadata=parameters.remove_metadata)
    xrefs_user = calculate_xrefs(xrefs, len(xrefs_body), offset=body.getNextOffset())

    if parameters.update_xrefs:
        xrefs_user.append(PDFCore.PDFCrossRefEntry(0, 0xffff, 'f'))

    # Add them to the body
    for index in sorted(xrefs):
        _, obj = xrefs[index]
        if xrefs_user[index].objectOffset != body.getNextOffset():
            raise AssertionError((body.getNextOffset(), table[index].objectOffset))
        body.setObject(id=index + len(xrefs_body), object=obj)

    # Iterate through each object in our body, and send it to our writer
    [ P.send(body.objects[index]) for index in sorted(body.objects) ]

    # Now we can start adding our xref stuff based on what the user gave us
    xrefs_offset = body.getNextOffset()
    xrefs = xrefs_body if parameters.update_xrefs else xrefs_user
    if parameters.update_xrefs:
        subsection = PDFCore.PDFCrossRefSubSection(0, len(xrefs), xrefs)
        section = PDFCore.PDFCrossRefSection()
        section.addSubsection(subsection)
        P.send(section)

    # Lastly...the trailer, which should point to our table.
    infile, = trailer_files
    trailer = load_trailer(infile)

    # Update the last crossref section with the user-specified xrefs
    trailer.setLastCrossRefSection(xrefs_offset if parameters.update_xrefs else xrefs[0].objectOffset)

    # If there aren't any xrefs, then there's no crossref section here,
    # so explicitly hack it into the trailer's lastCrossRefSection
    if trailer.lastCrossRefSection is None:
        print("No xrefs were found! Using an empty string for the last crossref section offset")
        trailer.lastCrossRefSection = ''

    # If we were asked to update it, then fix the size.
    if parameters.update_xrefs:
        trailer.dict.setElement('/Size', PDFCore.PDFNum("{:d}".format(max(index for index in body.objects) if body.objects else 0)))

    # That's it.
    P.send(trailer)
    P.close()
    return 0

def halp():
    P = argparse.ArgumentParser(description='What The Fuck, PDF?', add_help=True)
    P.add_argument('filename', type=str, help='a portable document file name')

    Paction = P.add_subparsers(dest='action', description='whatever the fuck you want to do', metavar='ACTION')

    Plist = Paction.add_parser('list', help='enumerate the objects within a pdf file')
    if Plist:
        Plist.add_argument('-v', '--verbose', action='store_true', help='print out verbose information')

    Pextract = Paction.add_parser('extract', help='extract all of the objects within a pdf file to a directory')
    if Pextract:
        Pextract.add_argument('directory', nargs='+', help='specify the directories to dump objects from each trailer into')
        Pextract.add_argument('-c', '--compressed', action='store_true', default=False, help='extract objects with decompressing them')
        Pextract.add_argument('-F', '--fix-offsets', dest='fix_offsets', action='store_true', default=False, help='fix offsets within the trailer and any xrefs')

    Pcreate = Paction.add_parser('create', help='combine all of the files in a directory into a pdf file')
    if Pcreate:
        Pcreate.add_argument('files', nargs='*', help='specify the directory containing the objects to write')
        Pcreate.add_argument('-B', '--set-binary-chars', dest='set_binary', action='store', type=operator.methodcaller('decode','hex'), default='', help='set the binary comment at the top of the pdf')
        Pcreate.add_argument('-V', '--set-version', dest='set_version', action='store', type=float, default=1.7, help='set the pdf version to use')
        Pcreate.add_argument('-s', '--skip-update-metadata', dest='update_metadata', action='store_false', default=True, help='do not update the metadata for each object (Filter and Length) when examining the object\'s contents')
        Pcreate.add_argument('-R', '--remove-metadata', dest='remove_metadata', action='store_true', default=False, help='remove the Filter field from the object metadata when there isn\'t an encoding (*.Binary)')
        Pcreate.add_argument('-I', '--ignore-xrefs', dest='update_xrefs', action='store_false', default=True, help='ignore rebuilding of the xrefs (use the provided objects)')

    Phelp = Paction.add_parser('help', help='yep')
    return P
halp = halp()

if __name__ == '__main__':
    import sys
    params = halp.parse_args()

    if params.action in {'list'}:
        result = do_listpdf(params.filename, params)

    elif params.action in {'extract'}:
        result = do_readpdf(params.filename, params)

    elif params.action in {'create'}:
        result = do_writepdf(params.filename, params)

    elif params.action in {'help'}:
        result = halp.print_help() or 0

    else:
        result = halp.print_usage() or 1

    sys.exit(result)
