import functools, itertools, types, builtins, operator, six
import argparse, json, math, os.path, codecs, heapq
import PDFCore

PDFCodec = codecs.lookup('iso8859-1')
infile = '/home/user/audit/nitro/nitro_for_ali/nitro_60e_non_minimized/poc.pdf'

def ParsePDF(infile):
    P = PDFCore.PDFParser()
    _, p = P.parse(infile, forceMode=True, looseMode=True, manualAnalysis=False)
    return p

FormatStream = "{:d} {:d} obj".format

def PDFEncode(element):
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
        return res.encode('hex')
    elif isinstance(element, PDFCore.PDFReference):
        res = element.getValue()
        return str(res)
    elif isinstance(element, PDFCore.PDFArray):
        iterable = element.getElements()
        return [ PDFEncode(item) for item in iterable ]
    elif isinstance(element, PDFCore.PDFDictionary):
        iterable = element.getElements()
        return { str(name) : PDFEncode(item) for name, item in iterable.items() }
    raise TypeError(element)

def PDFDecode(instance):
    if isinstance(instance, PDFCore.PDFObject):
        return instance
    elif isinstance(instance, dict):
        # ensure the names in the dictionary are proper strings...
        decoded = { name if isinstance(name, unicode) else PDFCodec.decode(name, 'ignore')[0] : item for name, item in instance.items() }
        res = { PDFCodec.encode(name, 'ignore')[0] : PDFDecode(item) for name, item in decoded.items() }
        return PDFCore.PDFDictionary(elements=res)

    elif isinstance(instance, list):
        res = [ PDFDecode(item) for item in instance ]
        return PDFCore.PDFArray(elements=res)

    elif isinstance(instance, float):
        return PDFCore.PDFNum("{:f}".format(instance))

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
            if len(res) % 2 == 0 and res.lower() == res and res.translate(None, b' \t\n') == res:
                res.decode('hex')
                return PDFCore.PDFHexString(res)

        except TypeError:
            pass

        # forget it, it's a string
        return PDFCore.PDFString(res)
    raise TypeError(instance)

def fakeencode(filter, meta, data):
    res = PDFCore.PDFObjectStream(rawDict=meta.getRawValue())
    res.elements = meta.getElements()
    res.decodedStream = data
    res.isEncodedStream = True
    res.filter = PDFCore.PDFName("/{:s}".format(filter))
    res.encode()
    return res.encodedStream

def do_listpdf(infile, parameters):
    P = ParsePDF(infile)
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

def do_readversion(pdf, version, path, parameters):
    stats = pdf.getStats()

    Fstream = operator.methodcaller('getRawStream' if parameters.compressed else 'getStream')
    Felement = operator.methodcaller('getRawValue' if parameters.compressed else 'getValue')

    _, items = stats['Versions'][version]['Objects']
    for index in items:
        object = pdf.getObject(index, version=version)
        stats = object.getStats()

        Fobjectname = "{:d}_0_obj".format
        Fdump = functools.partial(json.dump, encoding=PDFCodec.name, indent=4, sort_keys=True)
        Ftypename = lambda element: element.__class__.__name__

        if stats['Errors'] and int(stats['Errors']) > 0:
            print("Errors in trailer {:d} ({:s}) with {:s}: {:d}".format(version, path, Fobjectname(index), int(stats['Errors'])))

        if isinstance(object, PDFCore.PDFStream):
            if stats.get('Decoding Errors', False) or parameters.compressed:
                Fstream = operator.methodcaller('getRawStream')
                suffix = 'Binary'
            else:
                Fstream = operator.methodcaller('getStream')
                suffix = stats.get('Filters', 'Binary').translate(None, '/')
            stream = Fstream(object)

            stream_name = '.'.join([Fobjectname(index), suffix])
            with open(os.path.join(path, stream_name), 'wb') as out:
                out.write(stream)

        elements = PDFEncode(object)

        elements_name = '.'.join([Fobjectname(index), 'json'])
        Fdump(elements, open(os.path.join(path, elements_name), 'wt'))

    # Last thing to do is to write our trailer and then we're done...
    stream, section = pdf.trailer[version]

    elements_name = '.'.join(['trailer', 'json'])
    Fdump(elements, open(os.path.join(path, elements_name), 'wt'))
    if not stream:
        return True

    stream_name = '.'.join(['trailer', 'xref'])
    with open(os.path.join(path, stream_name), 'wb') as out:
        out.write(stream.toFile())
        out.write('\n')
    return True

def do_readpdf(infile, parameters):
    P = ParsePDF(infile)
    position = P.getOffsets()
    stats = P.getStats()

    if len(stats['Versions']) != len(parameters.directory):
        count = len(stats['Version'])
        print("The input document that was specified ({:s}) contains {:d} individual trailers!".format(infile, count))
        print('')
        print("Please provide {:d} paths to extract each trailer into in order to continue!".format(count))
        print('')
        raise ValueError("Only {:d} directories were provided...".format(len(parameters.directory)))

    for i, path in enumerate(parameters.directory):
        if not os.path.isdir(path):
            raise OSError(path)
        do_readversion(P, i, path, parameters)

    return 0

def object_size(objects, index, generation=0):
    _, obj = objects[index]

    # we need to calculate this ourselves because peepdf doesn't expose this
    # to us in any form. the author instead hardcodes this calculation
    fmt = '{:d} {:d} obj\n{:s}\nendobj\n'.format
    return len(fmt(index, generation, obj.toFile()))

def collect_files(paths):
    result, trailers = {}, {}
    for item in paths:
        if not os.path.isfile(item):
            print("Skipping non-file path: {:s}".format(item))
            continue
        fullname = os.path.basename(item)
        name, ext = os.path.splitext(fullname)

        # validate our name format
        components = name.split('_')
        if not operator.contains({2, 3}, len(components)):
            print("Skipping path due to invalid format: {:s}".format(item))
            continue

        if len(components) == 2:
            trailer, index = components
            if trailer == 'trailer':
                try:
                    int(index)

                except ValueError:
                    pass

                else:
                    trailers.setdefault(int(index), []).append(item)
                    continue

            print("Skipping path due to invalid trailer format: {:s}".format(item))
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
    return result, trailers

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

def pairup_trailers(input):
    result = {}

    Ftrailername = "trailer_{:d}".format
    for index, files in input.items():

        # pair up our files
        meta, xrefs = [], []
        for item in files:
            fullname = os.path.basename(item)
            name, ext = os.path.splitext(fullname)
            if name != Ftrailername(index) or not operator.contains({'.json', '.xref'}, ext):
                print("Skipping path for trailer {:d} due to invalid name: {:s}".format(index, item))
                continue
            if ext == '.json':
                meta.append(item)
            elif ext == '.xref':
                xrefs.append(item)
            else:
                raise ValueError(fullname, name, ext)
            continue

        # if no metafile was found, then skip this object
        if len(meta) == 0:
            print("Skipping trailer {:d} as no metafile was found: {!r}".format(index, meta))
            continue

        # warn the user if they provided more than one file for a single object
        if len(meta) > 1:
            print("More than one metafile was specified for trailer {:d}: {!r}".format(index, meta))

        if len(xrefs) > 1:
            print("More than one xref table was specified for trailer {:d}: {!r}".format(index, xrefs))

        result[index] = (meta[0], xrefs[0] if len(xrefs) > 0 else None)
    return result

def load_body(pairs):
    body = {}
    for index, (metafile, contentfile) in pairs.items():
        metadict = json.load(open(metafile, 'rt'))

        if contentfile:
            _, res = os.path.splitext(contentfile)
            _, filter = res.split('.', 1)

            meta, data = PDFDecode(metadict), open(contentfile, 'rb').read()

            # the other of peepdf seems to smoke crack, so we'll explicitly
            # modify the fields to get his shit to work...
            stream = PDFCore.PDFObjectStream(rawDict=meta.getRawValue())
            stream.elements = meta.getElements()
            stream.decodedStream = data

            if filter.lower() == u'binary':
                body[index] = None, stream
                continue

            stream.isEncodedStream = True
            stream.filter = PDFCore.PDFName("/{:s}".format(filter))
            stream.encode()
            body[index] = stream.filter, stream

        else:
            body[index] = None, PDFDecode(metadict)
        continue
    return body

def load_trailers(pairs):
    result = {}
    for index in sorted(pairs):
        metafile, xreftable = pairs[index]

        metadict = json.load(open(metafile, 'rt'))
        meta = PDFDecode(metadict)

        if xreftable is None:
            result[index] = meta, None
            continue

        data = open(xreftable, 'rb').read()
        result[index] = meta, data

    # collect our results into a table
    table = []
    for index in sorted(result):
        meta, xrefs = result[index]
        table.append((meta, xrefs))
    return table

def update_body(objects):

    # Update the objects dict in-place
    for index in sorted(objects):
        flt, obj = objects[index]
        Fobject = lambda object, index: u"{:s} object {:d}".format(object.getType(), index)
        Ffieldvalue = lambda field: u"{:s}({!r})".format(field.__class__.__name__, field.getValue())
        Ffieldname = lambda name: u"`/{:s}`".format(name)

        # Ensure that we're an object stream
        if not isinstance(obj, PDFCore.PDFObjectStream):
            print("Skipping {:s}..".format(Fobject(obj, index)))
            continue

        meta = obj.getElements()
        size = len(obj.getRawStream())

        # And that our metadata is a dict that we can update
        meta_obj = PDFDecode(meta)
        if not isinstance(meta_obj, PDFCore.PDFDictionary):
            t = meta_obj.__class__
            print("Skipping {:s} with invalid metadata type ({!s})".format(Fobject(obj, index), t.__name__))
            continue

        meta_update = {}

        # First check if we need update the /Length for the stream
        if not operator.contains(meta, u'/Length'):
            print("{:s} does not have a {:s} field...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length')))

        elif not isinstance(meta[u'/Length'], PDFCore.PDFNum):
            t = PDFCore.PDFNum
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length'), Ffieldvalue(meta['/Length']), t.__name__))

        elif int(meta[u'/Length'].getValue()) != size:
            meta_update[u'/Length'] = PDFCore.PDFNum(u"{:d}".format(size))

        # Now check to see if the /Filter needs to be fixed
        if flt is None and not operator.contains(meta, '/Filter'):
            pass

        elif not operator.contains(meta, u'/Filter'):
            print("{:s} does not have a {:s} field...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Filter')))

        elif not isinstance(meta[u'/Filter'], PDFCore.PDFName):
            t = PDFCore.PDFName
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Filter'), Ffieldvalue(meta['/Filter']), t.__name__))

        elif flt is None:
            meta_update[u'/Filter'] = None

        elif meta[u'/Filter'].getValue() != flt.getValue():
            meta_update[u'/Filter'] = flt

        # Check if anything needs to be updated and then do it
        if any(operator.contains(meta_update, name) for name in [u'/Filter', u'/Length']):
            print("Updating the fields for {:s} object {:d}: {!s}".format(obj.getType(), index, ' '.join('='.join([name.split('/',1)[1], '<Removed>' if item is None else Ffieldvalue(item)]) for name, item in meta_update.items())))

            remove = { name for name, item in meta_update.items() if item is None }
            update = { name : meta_update[name] for name in meta_update if name not in remove }
            meta.update(update)
            [ meta.pop(name) for name in remove ]

        # Re-assign our metadata the stream directly because peepdf sucks
        obj.rawValue = PDFCore.PDFDictionary(elements=meta).getRawValue()
        obj.elements = meta

    # That's it, we've updated the metadata for each object
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

def process_xrefs(objects, indices, offset=0):
    table = []
    for index in sorted(objects):
        _, obj = objects[index]
        #size = len(obj.getRawValue())
        size = object_size(objects, index)
        bounds = offset, offset + size
        table.append((bounds, index))
        offset += size

    # we're going to sort our /Prev offsets because this is intended to be
    # incrementally updated, so we should be able to figure out what our
    # chain will look like by moonwalking this data.
    resultheap = []
    for index in indices:
        _, obj = objects[index]
        meta = obj.getElements()
        if operator.contains(meta, b'/Prev'):
            heapq.heappush(resultheap, (int(meta[b'/Prev'].getValue()), index))
        else:
            heapq.heappush(resultheap, (None, index))
        continue

    # if we found no streams, then return nothing because we'll need to add
    # our table in the trailer.
    if len(resultheap) == 0:
        return [None]

    # first element should always be our end
    none, start = resultheap[0]
    if none is not None:
        heapq.heappush(resultheap, (None, -1))
        print('Warning: Unable to find the initial XRef stream')
    _, initial = resultheap.pop(0)

    # now that things are sorted, let's figure out which objects that each
    # offset points to
    refs = {start : None}
    for _, index in resultheap:
        _, obj = objects[index]
        offset = int(meta[b'/Prev'].getValue())
        found = next((index for (left, right), index in table if left <= offset < right), None)
        if find is None:
            print("Warning: Unable to find index for offset {:+#x} referenced by object {:d}".format(offset, index))
            continue
        refs[index] = found

    # okay, now we can figure out which order this goes
    current, result = start, [start]
    while current is not None:
        if not operator.contains(refs, current):
            break
        result.append(refs[current])
        current = refs[current]
    if result[-1] is not None:
        print("Warnings: XRef streams reference a stream that does not exist!")
    return result

def calculate_xrefs(objects, offset=0):
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
        #offset += len(obj.getRawValue())
        offset += object_size(objects, index)
    return result + [PDFCore.PDFCrossRefEntry(offset, 0, 'n')]

#import glob
#files = glob.glob('work/*')
def do_writepdf(outfile, parameters):

    # first collect all of our object names
    object_files, trailer_files = collect_files(parameters.files)
    object_pairs = pairup_files(object_files)
    trailer_pairs = pairup_trailers(trailer_files)

    # create our pdf instance
    HEADER = '%PDF-X.x\n'

    P = PDFCore.PDFFile()
    P.setHeaderOffset(0)
    P.version = "{:.1f}".format(parameters.set_version)
    if parameters.set_binary:
        P.binary = True
        P.binaryChars = parameters.set_binary
    offset = 0x11

    # build our pdf body and update it if necessary
    objects = load_body(object_pairs)
    if parameters.update_metadata:
        objects = update_body(objects)

    # find all our previous xrefs
    trailers = load_trailers(trailer_pairs)
    xavailable = find_xrefs(objects)
    xstreams = process_xrefs(objects, xavailable, offset=offset)

    # if we couldn't find a starting xref, then we'll force the last object
    # to be one by removing it's /Prev field
    if parameters.update_xrefs:
        if not operator.contains(xstreams, None):
            _, obj = objects[xstreams[-1]]
            meta = obj.getElements()
            meta.pop(b'/Prev')
            obj.rawValue = PDFCore.PDFDictionary(elements=meta).getRawValue()
            obj.elements = meta
            xstreams.append(None)

    # okay, now we finally have a place to start. so calculate our initial
    # xrefs for each object that we're going to keep.
    xrefs = calculate_xrefs(objects, offset=offset)

    # I think that was it...so we can now finally rebuild the body
    body = PDFCore.PDFBody()
    body.setNextOffset(offset)
    for index in sorted(objects):
        _, obj = objects[index]
        assert xrefs[index].objectOffset == body.getNextOffset()
        body.setObject(id=index, object=obj)

    # If we were asked to update our xrefs, then we'll need to add just
    # one more object here..
    if params.update_xrefs and parameters.set_version <= 1.5:
        xrefs.append(PDFCore.PDFCrossRefEntry(body.getNextOffset(), 0, 'n'))
        xrefs.append(PDFCore.PDFCrossRefEntry(0, 0xffff, 'f'))

        # append our last empty slot
        section = PDFCore.PDFCrossRefSubSection(0, len(xrefs), xrefs)

        # now to build a fucking table
        table = PDFCore.PDFCrossRefSection()
        table.addSubsection(section)

        trailer_meta = PDFCore.PDFDictionary({})
        trailer_meta.setElement(b'/Size', PDFDecode(len(xrefs)))
        # FIXME

    elif parameters.update_xrefs:
        raise NotImplementedError

    else:
        _, table = objects[xstreams[0]]

    # Okay, back to the PDFFile. Now we can start building things...
    P.addBody(body)
    P.addNumObjects(body.getNumObjects())
    P.addNumObjects(body.getNumStreams())
    P.addNumEncodedStreams(body.getNumEncodedStreams())
    P.addNumDecodingErrors(body.getNumDecodingErrors())
    P.addCrossRefTableSection([table, None])

    # Lastly...the trailer, which should point to our table.
    trailer = PDFCore.PDFTrailer(trailer_meta, body.getNextOffset())
    trailer.setLastCrossRefSection(xrefs[xstreams[0]].objectOffset)
    trailer.setNumObjects(len(xrefs))
    print trailer.toFile()

    return 0
    #if parameters.update_xrefs:
    #for i in sorted(objects):
    #    _, obj = objects[i]
    #    if isinstance(obj, PDFCore.PDFObjectStream):
    #        print obj.getElements()
    #    elif isinstance(obj, PDFCore.PDFDictionary):
    #        print obj.getElements()
    print dir(obj)
    print objects[21][1].toFile()
    print P.getOffsets()

    return 0
    if False:
        flt, obj = objects[5]
        print flt.getValue()
        print obj.getElements()
        print len(obj.getRawStream())   # size of (encoded) stream
        print obj.getRawValue()         # entire object size
        print PDFEncode(PDFDecode(obj.getElements()))   # back to a dictionary

    oldtrailer = []
    xrefs, body = [], PDFCore.PDFBody()
    for index in sorted(objects):
        flt, obj = objects[index]
        elements = obj.getElements()
        meta = [ PDFEncode(item) for item in elements ] if isinstance(elements, list) else { name : PDFEncode(item) for name, item in elements.items() }

        # skip our xrefs
        if isinstance(meta, dict) and meta.get('/Type', None) == '/XRef':
            oldtrailer.append((offset, obj))
            continue

        # add the object to our body
        body.setObject(id=index, object=obj)
        xrefs.append(PDFCore.PDFCrossRefEntry(offset, 0, 'n'))
        wtfdude = body.objects[index]
        offset += len(wtfdude.toFile())

    body.setNextOffset(offset)

    # update pdf
    P.addBody(body)
    P.addNumObjects(body.getNumObjects())
    P.addNumStreams(body.getNumStreams())
    P.addNumEncodedStreams(body.getNumEncodedStreams())
    P.addNumDecodingErrors(body.getNumDecodingErrors())

    # we can't trust peepdf, so don't let it do any of these
    P.trailer = [[None, None]]
    P.crossRefTable = [[None, None]]

    # add xrefs
    if False:
        print oldxrefs
        #section = PDFCore.PDFCrossRefSubSection(0, len(xrefs), xrefs)
        section = PDFCore.PDFCrossRefSubSection(0, 0, xrefs)
        xrefsection = PDFCore.PDFCrossRefSection()
        xrefsection.addSubsection(section)
        size = len(xrefs) * 20 + len('startxref\n')
        xrefsection.setSize(size)
        P.crossRefTable = [[xrefsection, None]]
        #P.addCrossRefTableSection([xrefsection, None])
        offset += size

    # save pdf
    P.setSize(offset)
    P.updateStats()
    fucking, stupid = P.save(outfile)
    if fucking:
        raise ValueError(stupid)

    # append trailer manually because the other of peepdf is fucking crazy
    (traileroffset, trailerobj), = oldtrailer
    res = PDFCore.PDFDictionary(elements=trailerobj.getElements())
    trailer = PDFCore.PDFTrailer(res)
    trailer.setLastCrossRefSection(str(body.nextOffset))
    trailer.setEOFOffset(offset)

    with open(outfile, 'ab') as out:
        out.write(trailer.toFile())

    return 0

def halp():
    P = argparse.ArgumentParser(description='What The Fuck, PDF?', add_help=True)
    P.add_argument('filename', type=str, help='a portable document file name')

    Paction = P.add_subparsers(dest='action', description='whatever the fuck you want to do', metavar='ACTION')

    Plist = Paction.add_parser('list', help='enumerate the objects within a pdf file')
    if Plist:
        Plist.add_argument('-v', '--verbose', action='store_true', help='print out verbose information')

    Pread = Paction.add_parser('read', help='read the objects within a pdf file')
    if Pread:
        Pread.add_argument('directory', nargs='+', help='specify the directories to dump objects from each trailer into')
        Pread.add_argument('-c', '--compressed', action='store_true', default=False, help='extract objects with decompressing them')

    Pcombine = Paction.add_parser('write', help='write the files in a directory into a pdf file')
    if Pcombine:
        Pcombine.add_argument('files', nargs='*', help='specify the directory containing the objects to write')
        Pcombine.add_argument('-B', '--set-binary-chars', dest='set_binary', action='store', type=operator.methodcaller('decode','hex'), default='', help='set the binary comment at the top of the pdf')
        Pcombine.add_argument('-V', '--set-version', dest='set_version', action='store', type=float, default=1.7, help='set the pdf version to use')
        Pcombine.add_argument('-U', '--update-metadata', dest='update_metadata', action='store_true', default=False, help='update the metadata for each object (Filter and Length) by looking at the object\'s contents')
        Pcombine.add_argument('-I', '--ignore-xrefs', dest='update_xrefs', action='store_false', default=True, help='ignore rebuilding of the xrefs (use one of the provided objects)')

    Phelp = Paction.add_parser('help', help='yep')
    return P
halp = halp()

if __name__ == '__main__':
    import sys
    params = halp.parse_args()

    if params.action == 'list':
        result = do_listpdf(params.filename, params)

    elif params.action == 'read':
        result = do_readpdf(params.filename, params)

    elif params.action == 'write':
        result = do_writepdf(params.filename, params)

    elif params.action == 'help':
        result = halp.print_help() or 0

    else:
        result = halp.print_usage() or 1

    sys.exit(result)
