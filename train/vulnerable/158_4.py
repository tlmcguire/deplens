
from __future__ import print_function

__version__ = "0.3"


from PIL import Image, ImageFile, _binary
import os, tempfile

i8 = _binary.i8
i16 = _binary.i16be
i32 = _binary.i32be
o8 = _binary.o8

COMPRESSION = {
    1: "raw",
    5: "jpeg"
}

PAD = o8(0) * 4


def i(c):
    return i32((PAD + c)[-4:])

def dump(c):
    for i in c:
        print("%02x" % i8(i), end=' ')
    print()


class IptcImageFile(ImageFile.ImageFile):

    format = "IPTC"
    format_description = "IPTC/NAA"

    def getint(self, key):
        return i(self.info[key])

    def field(self):
        s = self.fp.read(5)
        if not len(s):
            return None, 0

        tag = i8(s[1]), i8(s[2])

        if i8(s[0]) != 0x1C or tag[0] < 1 or tag[0] > 9:
            raise SyntaxError("invalid IPTC/NAA file")

        size = i8(s[3])
        if size > 132:
            raise IOError("illegal field length in IPTC/NAA file")
        elif size == 128:
            size = 0
        elif size > 128:
            size = i(self.fp.read(size-128))
        else:
            size = i16(s[3:])

        return tag, size

    def _is_raw(self, offset, size):

        return 0

        self.fp.seek(offset)
        t, sz = self.field()
        if sz != size[0]:
            return 0
        y = 1
        while True:
            self.fp.seek(sz, 1)
            t, s = self.field()
            if t != (8, 10):
                break
            if s != sz:
                return 0
            y = y + 1
        return y == size[1]

    def _open(self):

        while True:
            offset = self.fp.tell()
            tag, size = self.field()
            if not tag or tag == (8,10):
                break
            if size:
                tagdata = self.fp.read(size)
            else:
                tagdata = None
            if tag in list(self.info.keys()):
                if isinstance(self.info[tag], list):
                    self.info[tag].append(tagdata)
                else:
                    self.info[tag] = [self.info[tag], tagdata]
            else:
                self.info[tag] = tagdata


        layers = i8(self.info[(3,60)][0])
        component = i8(self.info[(3,60)][1])
        if (3,65) in self.info:
            id = i8(self.info[(3,65)][0])-1
        else:
            id = 0
        if layers == 1 and not component:
            self.mode = "L"
        elif layers == 3 and component:
            self.mode = "RGB"[id]
        elif layers == 4 and component:
            self.mode = "CMYK"[id]

        self.size = self.getint((3,20)), self.getint((3,30))

        try:
            compression = COMPRESSION[self.getint((3,120))]
        except KeyError:
            raise IOError("Unknown IPTC image compression")

        if tag == (8,10):
            if compression == "raw" and self._is_raw(offset, self.size):
                self.tile = [(compression, (offset, size + 5, -1),
                             (0, 0, self.size[0], self.size[1]))]
            else:
                self.tile = [("iptc", (compression, offset),
                             (0, 0, self.size[0], self.size[1]))]

    def load(self):

        if len(self.tile) != 1 or self.tile[0][0] != "iptc":
            return ImageFile.ImageFile.load(self)

        type, tile, box = self.tile[0]

        encoding, offset = tile

        self.fp.seek(offset)

        outfile = tempfile.mktemp()
        o = open(outfile, "wb")
        if encoding == "raw":
            o.write("P5\n%d %d\n255\n" % self.size)
        while True:
            type, size = self.field()
            if type != (8, 10):
                break
            while size > 0:
                s = self.fp.read(min(size, 8192))
                if not s:
                    break
                o.write(s)
                size = size - len(s)
        o.close()

        try:
            try:
                self.im = Image.core.open_ppm(outfile)
            except:
                im = Image.open(outfile)
                im.load()
                self.im = im.im
        finally:
            try: os.unlink(outfile)
            except: pass


Image.register_open("IPTC", IptcImageFile)

Image.register_extension("IPTC", ".iim")


def getiptcinfo(im):

    from PIL import TiffImagePlugin, JpegImagePlugin
    import io

    data = None

    if isinstance(im, IptcImageFile):
        return im.info

    elif isinstance(im, JpegImagePlugin.JpegImageFile):
        try:
            app = im.app["APP13"]
            if app[:14] == "Photoshop 3.0\x00":
                app = app[14:]
                offset = 0
                while app[offset:offset+4] == "8BIM":
                    offset = offset + 4
                    code = JpegImagePlugin.i16(app, offset)
                    offset = offset + 2
                    name_len = i8(app[offset])
                    name = app[offset+1:offset+1+name_len]
                    offset = 1 + offset + name_len
                    if offset & 1:
                        offset = offset + 1
                    size = JpegImagePlugin.i32(app, offset)
                    offset = offset + 4
                    if code == 0x0404:
                        data = app[offset:offset+size]
                        break
                    offset = offset + size
                    if offset & 1:
                        offset = offset + 1
        except (AttributeError, KeyError):
            pass

    elif isinstance(im, TiffImagePlugin.TiffImageFile):
        try:
            data = im.tag.tagdata[TiffImagePlugin.IPTC_NAA_CHUNK]
        except (AttributeError, KeyError):
            pass

    if data is None:
        return None

    class FakeImage:
        pass
    im = FakeImage()
    im.__class__ = IptcImageFile

    im.info = {}
    im.fp = io.BytesIO(data)

    try:
        im._open()
    except (IndexError, KeyError):
        pass

    return im.info
