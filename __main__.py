import functools, itertools, types, builtins, operator, six
import argparse, json, math, os.path
import PDFCore

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
        res = { name.encode('latin1') : PDFDecode(item) for name, item in instance.items() }
        return PDFCore.PDFDictionary(elements=res)
    elif isinstance(instance, list):
        res = [ PDFDecode(item) for item in instance ]
        return PDFCore.PDFArray(elements=res)
    elif isinstance(instance, float):
        return PDFCore.PDFNum("{:f}".format(instance))
    elif isinstance(instance, six.integer_types):
        return PDFCore.PDFNum("{:d}".format(instance))
    elif isinstance(instance, six.string_types):
        res = instance.encode('latin1')

        # check if it's a name
        if res.startswith(b'/'):
            return PDFCore.PDFName(res)

        # check if it's a reference
        try:
            if len(res.split(' ')) == 3:
                index, generation, reference = res.split(' ', 3)

                int(index)
                assert int(generation) == 0
                assert reference == 'R'
                return PDFCore.PDFReference(index, generation)

        except (AssertionError, ValueError):
            pass

        # check if it's a hexstring
        try:
            if len(res) % 2 == 0 and res.lower() == res and res.translate(None, ' \t\n') == res:
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
    position, = P.getOffsets()
    stats = P.getStats()

    if len(stats['Versions']) != 1:
        raise AssertionError(stats['Versions'])
    V, = stats['Versions']

    print("Parsed file: {:s}".format(infile))
    if P.binary:
        print("BinaryChars: {:s}".format(P.binaryChars.encode('hex')))
    print("Version: {:.1f}".format(float(stats['Version'])))
    print("Total size: {size:+#x} ({size:d})".format(size=int(stats['Size'])))
    print("MD5: {:s}".format(stats['MD5']))
    print("SHA1: {:s}".format(stats['SHA1']))
    print("SHA256: {:s}".format(stats['SHA256']))
    print('')

    offset, _ = position['header']
    print("Header: {:#x}".format(offset))
    offset, size = position['trailer']
    print("Trailer: {:#x}{:+x}".format(offset, size))
    offset, _ = position['eof']
    print("%%EOF: {:#x}".format(offset))
    print('')

    count, items = V['Streams']
    print("Number of streams: {:d}".format(int(stats['Streams'])))
    print("Indices of streams: {:s}".format(', '.join(map("{:d}".format, items))))
    count, item = V['Encoded']
    print("Indices of encoded streams: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
    count, item = V['Decoding Errors']
    print("Streams with decoding errors: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
    print('')

    count, items = V['Xref Streams']
    print("Number of xref streams: {:d}".format(int(count)))
    print("Indices of xref streams: {:s}".format(', '.join(map("{:d}".format, items))))
    print('')

    count, items = V['Object Streams']
    print("Number of object streams: {:d}".format(int(count)))
    print("Indices of object streams: {:s}".format(', '.join(map("{:d}".format, items))))
    count, item = V['Errors']
    print("Objects with errors: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
    print('')

    count, items = V['Objects']
    print("Total number of objects: {:d}".format(int(stats['Objects'])))
    print("Indices of objects: {:s}".format(', '.join(map("{:d}".format, items))))
    _, items = V['Compressed Objects']
    print("Indices of compressed objects: ({:+d}) {:s}".format(int(count), ', '.join(map("{:d}".format, items))))
    print('')

    max_digits = map(max, zip(*position['objects']))
    bases = [ 10, 0x10, 0x10 ]
    digits_id, digits_pos, digits_sz = (math.trunc(math.ceil(math.log(item, base))) for item, base in zip(max_digits, bases))

    print("Object position:")
    for id, offset, size in position['objects']:
        object = P.getObject(id)
        meta = object.getStats()
        dictionary = object.getElements()
        if isinstance(dictionary, dict):
            description = {name : item.getRawValue() for name, item in sorted(dictionary.items())}
        else:
            description = [ item.getRawValue() for item in dictionary ]
        print("[{offset:#0{digits_pos:d}x}{size:+0{digits_sz:d}x}] {:d} {:d} obj {padding:s}: {dict!s}".format(id, 0, offset=offset, size=size, dict=description, digits_pos=2+digits_pos, digits_sz=1 + digits_sz, padding=' '*(digits_id - len("{:d}".format(id)))))

    return 0

def do_readpdf(infile, parameters):
    P = ParsePDF(infile)
    position, = P.getOffsets()
    stats = P.getStats()

    if len(stats['Versions']) != 1:
        raise AssertionError(stats['Versions'])
    V, = stats['Versions']

    path = parameters.directory
    if not os.path.isdir(path):
        raise OSError(path)

    Fstream = operator.methodcaller('getRawStream' if parameters.compressed else 'getStream')
    Felement = operator.methodcaller('getRawValue' if parameters.compressed else 'getValue')

    _, items = V['Objects']
    for index in items:
        object = P.getObject(index)
        stats = object.getStats()

        Fobjectname = "{:d}_0_obj".format
        Fdump = functools.partial(json.dump, encoding='latin1', indent=4, sort_keys=True)
        Ftypename = lambda element: element.__class__.__name__

        if stats['Errors'] and int(stats['Errors']) > 0:
            print("Errors with {:s}: {:d}".format(Fobjectname(index), int(stats['Errors'])))

        if isinstance(object, PDFCore.PDFStream):
            if stats['Decoding Errors'] or parameters.compressed:
                Fstream = operator.methodcaller('getRawStream')
                suffix = 'Binary'
            else:
                Fstream = operator.methodcaller('getStream')
                suffix = stats['Filters'].translate(None, '/')
            stream = Fstream(object)

            stream_name = '.'.join([Fobjectname(index), suffix])
            with open(os.path.join(parameters.directory, stream_name), 'wb') as out:
                out.write(stream)

        elements = PDFEncode(object)

        elements_name = '.'.join([Fobjectname(index), 'json'])
        Fdump(elements, open(os.path.join(parameters.directory, elements_name), 'wt'))
    return 0

def collect_files(paths):
    result = {}
    for item in paths:
        if not os.path.isfile(item):
            print("Skipping non-file path: {:s}".format(item))
            continue
        fullname = os.path.basename(item)
        name, ext = os.path.splitext(fullname)

        # validate our name format
        components = name.split('_')
        if len(components) != 3:
            print("Skipping path due to invalid format: {:s}".format(item))
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
    return result

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

            if filter.lower() == 'binary':
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

def update_body(objects):

    # Update the objects dict in-place
    for index in sorted(objects):
        flt, obj = objects[index]
        Fobject = lambda object, index: "{:s} object {:d}".format(object.getType(), index)
        Ffieldvalue = lambda field: "{:s}({!r})".format(field.__class__.__name__, field.getValue())
        Ffieldname = lambda name: "`/{:s}`".format(name)

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
        if not operator.contains(meta, '/Length'):
            print("{:s} does not have a {:s} field...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length')))

        elif not isinstance(meta['/Length'], PDFCore.PDFNum):
            t = PDFCore.PDFNum
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Length'), Ffieldvalue(meta['/Length']), t.__name__))

        elif int(meta['/Length'].getValue()) != size:
            meta_update['/Length'] = PDFCore.PDFNum("{:d}".format(size))

        # Now check to see if the /Filter needs to be fixed
        if flt is None and not operator.contains(meta, '/Filter'):
            pass

        elif not operator.contains(meta, '/Filter'):
            print("{:s} does not have a {:s} field...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Filter')))

        elif not isinstance(meta['/Filter'], PDFCore.PDFName):
            t = PDFCore.PDFName
            print("{:s} has a {:s} field {:s} not of the type {:s}...skipping its update!".format(Fobject(obj, index).capitalize(), Ffieldname('Filter'), Ffieldvalue(meta['/Filter']), t.__name__))

        elif flt is None:
            meta_update['/Filter'] = None

        elif meta['/Filter'].getValue() != flt.getValue():
            meta_update['/Filter'] = flt

        # Check if anything needs to be updated and then do it
        if any(operator.contains(meta_update, name) for name in ['/Filter', '/Length']):
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

#import glob
#files = glob.glob('work/*')
def do_writepdf(outfile, parameters):

    # first collect all of our object names
    object_files = collect_files(parameters.files)
    object_pairs = pairup_files(object_files)

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
        Pread.add_argument('directory', help='specify the directory to dump objects into')
        Pread.add_argument('-c', '--compressed', action='store_true', default=False, help='extract objects with decompressing them')

    Pcombine = Paction.add_parser('write', help='write the files in a directory into a pdf file')
    if Pcombine:
        Pcombine.add_argument('files', nargs='*', help='specify the directory containing the objects to write')
        Pcombine.add_argument('-B', '--set-binary-chars', dest='set_binary', action='store', type=operator.methodcaller('decode','hex'), default='', help='set the binary comment at the top of the pdf')
        Pcombine.add_argument('-V', '--set-version', dest='set_version', action='store', type=float, default=1.7, help='set the pdf version to use')
        Pcombine.add_argument('-U', '--update-metadata', dest='update_metadata', action='store_true', default=False, help='update the metadata for each object (Filter and Length) by looking at the object\'s contents')

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
