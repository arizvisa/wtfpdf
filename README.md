# Intro

Wtf, PDF? Why are there no good tools that interact with this format? Why are
all parsers for this loading the whole file into memory? Who actually really
believes that a PDF-specific repl with custom commands is a legit way to
interact with this format? Why?? Like seriously...why?

## General
If you ever asked one of these questions while searching for something to
flexibly interact with this format, then this tool is for you. It does two
main things. One of them is to decompose all the objects in a PDF (utilizing
magical filenames), whilst also decoding streams with any known filters. The
second thing is that this tool can take a list of files (with magical filenames)
and combine them back into a PDF.

The idea is that you can now use a text-editor and standard file management to
modify the different parts of the PDF, and when you're done you can put it back
together again. Some options are provided to automatically update certain
fields, repair the xref table, change the header, etc.

This tool is somewhat dependent on the capabilities of the peepdf tool as
written by @jesparza. The GitHub repository of this tool can be found at
https://github.com/jesparza/peepdf. There's a number of issues with peepdf,
and so a lot of peepdf's capabilities were re-factored out of WTFPDF.

## Magical filenames?

What are magical filenames? They're essentially filenames with a hardcoded
syntax that communicates semantics back into WTFPDF. Objects/Streams will
have the format "$ID_0_obj.$SUFFIX", Trailers are named "trailer.$SUFFIX",
and cross-reference tables are named "xref_$INDEX.$SUFFIX". When combining
these files back into a PDF, the "$ID" will be used as the object identifer.
For the cross-reference tables, they will be inserted in the order given
by the "$INDEX". These filenames are case-sensitive.

    > PDF=/path/to/file.pdf
    > P=/path/to/extract/contents/
    ...
    > python /path/to/repository $PDF read "$P"
    ...
    > ls $P
    1_0_obj.json            3_0_obj.json       8_0_obj.json
    1_0_obj.Binary          3_0_obj.Binary     8_0_obj.Binary
    2_0_obj.json            5_0_obj.json       9_0_obj.ASCIIHexDecode,FlateDecode
    2_0_obj.FlateDecode     7_0_obj.json       10_0_obj.JPXDecode,
    ...


### Magical suffixes (JSON)

The filename suffix is probably the most important part of this tool. A suffix
of ".json" is the metadata associated with a given Object/Stream. The contents
of these types of files can be edited and then used to set specific attributes
for the referenced object.

    > cat $P/1_0_obj.json
    {
        "/Lang": "en-US", 
        "/MarkInfo": {
            "/Marked": true
        }, 
        "/Metadata": "256 0 R", 
        "/Pages": "2 0 R", 
        "/StructTreeRoot": "27 0 R", 
        "/Type": "/Catalog", 
        "/ViewerPreferences": "257 0 R"
    }

### Magical suffixes (Filters)

Any other suffix is considered an encoding type for the object. There are a
number of encoding types that are supported by the PDF file format
specification, and only a handful of them are supported by peepdf. If an
Object/Stream could not be decoded, the content emitted by WTFPDF will have
a special ".Binary" extension. This suffix will result in WTFPDF inserting
the object into your target PDF byte-for-byte.

The other encoding types such as "ASCIIHexDecode", "ASCII85Decode", "LZWDecode",
or "FlateDecode" can be used. If a file has one of these suffixes, the file
will be encoded with that specific filter prior to inserting it into your target
PDF.

    > PDF=/path/to/file.pdf
    > P=/path/to/extract/contents/
    > python /path/to/repository $PDF read "$P"
    ...
    > mv $P/7_0_obj.Binary $P/7_0_obj.FlateDecode
    > cp $P/xref_0.FlateDecode $P/xref_1.ASCIIHexDecode

### Magical suffixes (Filter chains)

If the file suffix contains a "," character, then WTFPDF will assume that you're
telling it to encode the file with multiple filters when inserting it back into
the PDF. This is described in section 7.4.1 Filters (General) of the PDF
specification. If you want your file to be encoded with a chain of filters, but
there's only one filter you have in mind, then you can use a suffix that is
terminated with a ",".

As an example, one can simply rename the file they're interacting with to the
following filename.

    > mv $P/22_0_obj.FlateDecode $P/22_0_obj.DCTDecode,JPXDecode,LZWDecode
    > mv $P/24_0_obj.DCTDecode, $P/24_0_obj.CCITTFaxDecode

## Usage

This tool requires Python2 because Python3 is being over-run by crazies. To
use this, simply run Python2 with the path to the repository for WTFPDF.

The syntax for running this looks like the following. For more information
please review the command-line help for WTFPDF.

    > python /path/to/repository pdf-filename COMMAND [command-specific parameters]

There are 3 commands available, and are pretty self-explanatory:

  - list -- will dump the contents of the PDF using peepdf's parser
  - read -- parse the contents of a PDF into a specific directory
  - write -- given a list of files at the command-line, combine them into a PDF

### Reading

When reading a PDF, the path to the PDF must be provided. After giving WTFPDF
the "read" command, a number of directories will be required. This directory
will be where WTFPDF will extract the contents of the PDF to. An arbitrary
number of directories is necessary as there can be more than one Trailer inside
a PDF. The identifiers for each Object/Stream is scoped to the Trailer version.

    > python /path/to/repository myfile.pdf read myfile-pdf-contents-revision-0 myfile-pdf-contents-revision-1
    ...

There are some options that can be used to customize extraction. Please view
the command-line help for more information.

### Writing

When combining a PDF, globbing is of an utmost necessity. Make sure you're using
a proper shell that supports this. First start by giving the path to the PDF
you wish to create, followed by the "write" command. After giving WTFPDF the
"write" command, the rest of the command-line will be the list of files to
combine. These files will be paired up according to the description in the
"Magical filenames" section. After being paired up, the objects will be
sorted by their ID, and written to the path you gave it.

    > python /path/to/repository new.pdf write my-file-pdf-contents-revision-0/*
    ...

There are some options that can be used to customize building. Please view
the command-line help for more information.
