
__version__ = "0.6"

import array, struct
from PIL import Image, ImageFile, _binary
from PIL.JpegPresets import presets
from PIL._util import isStringType

i8 = _binary.i8
o8 = _binary.o8
i16 = _binary.i16be
i32 = _binary.i32be


def Skip(self, marker):
    n = i16(self.fp.read(2))-2
    ImageFile._safe_read(self.fp, n)

def APP(self, marker):

    n = i16(self.fp.read(2))-2
    s = ImageFile._safe_read(self.fp, n)

    app = "APP%d" % (marker&15)

    self.app[app] = s
    self.applist.append((app, s))

    if marker == 0xFFE0 and s[:4] == b"JFIF":
        self.info["jfif"] = version = i16(s, 5)
        self.info["jfif_version"] = divmod(version, 256)
        try:
            jfif_unit = i8(s[7])
            jfif_density = i16(s, 8), i16(s, 10)
        except:
            pass
        else:
            if jfif_unit == 1:
                self.info["dpi"] = jfif_density
            self.info["jfif_unit"] = jfif_unit
            self.info["jfif_density"] = jfif_density
    elif marker == 0xFFE1 and s[:5] == b"Exif\0":
        self.info["exif"] = s
    elif marker == 0xFFE2 and s[:5] == b"FPXR\0":
        self.info["flashpix"] = s
    elif marker == 0xFFE2 and s[:12] == b"ICC_PROFILE\0":
        self.icclist.append(s)
    elif marker == 0xFFEE and s[:5] == b"Adobe":
        self.info["adobe"] = i16(s, 5)
        try:
            adobe_transform = i8(s[1])
        except:
            pass
        else:
            self.info["adobe_transform"] = adobe_transform

def COM(self, marker):

    n = i16(self.fp.read(2))-2
    s = ImageFile._safe_read(self.fp, n)

    self.app["COM"] = s
    self.applist.append(("COM", s))

def SOF(self, marker):

    n = i16(self.fp.read(2))-2
    s = ImageFile._safe_read(self.fp, n)
    self.size = i16(s[3:]), i16(s[1:])

    self.bits = i8(s[0])
    if self.bits != 8:
        raise SyntaxError("cannot handle %d-bit layers" % self.bits)

    self.layers = i8(s[5])
    if self.layers == 1:
        self.mode = "L"
    elif self.layers == 3:
        self.mode = "RGB"
    elif self.layers == 4:
        self.mode = "CMYK"
    else:
        raise SyntaxError("cannot handle %d-layer images" % self.layers)

    if marker in [0xFFC2, 0xFFC6, 0xFFCA, 0xFFCE]:
        self.info["progressive"] = self.info["progression"] = 1

    if self.icclist:
        self.icclist.sort()
        if i8(self.icclist[0][13]) == len(self.icclist):
            profile = []
            for p in self.icclist:
                profile.append(p[14:])
            icc_profile = b"".join(profile)
        else:
            icc_profile = None
        self.info["icc_profile"] = icc_profile
        self.icclist = None

    for i in range(6, len(s), 3):
        t = s[i:i+3]
        self.layer.append((t[0], i8(t[1])//16, i8(t[1])&15, i8(t[2])))

def DQT(self, marker):


    n = i16(self.fp.read(2))-2
    s = ImageFile._safe_read(self.fp, n)
    while len(s):
        if len(s) < 65:
            raise SyntaxError("bad quantization table marker")
        v = i8(s[0])
        if v//16 == 0:
            self.quantization[v&15] = array.array("b", s[1:65])
            s = s[65:]
        else:
            return



MARKER = {
    0xFFC0: ("SOF0", "Baseline DCT", SOF),
    0xFFC1: ("SOF1", "Extended Sequential DCT", SOF),
    0xFFC2: ("SOF2", "Progressive DCT", SOF),
    0xFFC3: ("SOF3", "Spatial lossless", SOF),
    0xFFC4: ("DHT", "Define Huffman table", Skip),
    0xFFC5: ("SOF5", "Differential sequential DCT", SOF),
    0xFFC6: ("SOF6", "Differential progressive DCT", SOF),
    0xFFC7: ("SOF7", "Differential spatial", SOF),
    0xFFC8: ("JPG", "Extension", None),
    0xFFC9: ("SOF9", "Extended sequential DCT (AC)", SOF),
    0xFFCA: ("SOF10", "Progressive DCT (AC)", SOF),
    0xFFCB: ("SOF11", "Spatial lossless DCT (AC)", SOF),
    0xFFCC: ("DAC", "Define arithmetic coding conditioning", Skip),
    0xFFCD: ("SOF13", "Differential sequential DCT (AC)", SOF),
    0xFFCE: ("SOF14", "Differential progressive DCT (AC)", SOF),
    0xFFCF: ("SOF15", "Differential spatial (AC)", SOF),
    0xFFD0: ("RST0", "Restart 0", None),
    0xFFD1: ("RST1", "Restart 1", None),
    0xFFD2: ("RST2", "Restart 2", None),
    0xFFD3: ("RST3", "Restart 3", None),
    0xFFD4: ("RST4", "Restart 4", None),
    0xFFD5: ("RST5", "Restart 5", None),
    0xFFD6: ("RST6", "Restart 6", None),
    0xFFD7: ("RST7", "Restart 7", None),
    0xFFD8: ("SOI", "Start of image", None),
    0xFFD9: ("EOI", "End of image", None),
    0xFFDA: ("SOS", "Start of scan", Skip),
    0xFFDB: ("DQT", "Define quantization table", DQT),
    0xFFDC: ("DNL", "Define number of lines", Skip),
    0xFFDD: ("DRI", "Define restart interval", Skip),
    0xFFDE: ("DHP", "Define hierarchical progression", SOF),
    0xFFDF: ("EXP", "Expand reference component", Skip),
    0xFFE0: ("APP0", "Application segment 0", APP),
    0xFFE1: ("APP1", "Application segment 1", APP),
    0xFFE2: ("APP2", "Application segment 2", APP),
    0xFFE3: ("APP3", "Application segment 3", APP),
    0xFFE4: ("APP4", "Application segment 4", APP),
    0xFFE5: ("APP5", "Application segment 5", APP),
    0xFFE6: ("APP6", "Application segment 6", APP),
    0xFFE7: ("APP7", "Application segment 7", APP),
    0xFFE8: ("APP8", "Application segment 8", APP),
    0xFFE9: ("APP9", "Application segment 9", APP),
    0xFFEA: ("APP10", "Application segment 10", APP),
    0xFFEB: ("APP11", "Application segment 11", APP),
    0xFFEC: ("APP12", "Application segment 12", APP),
    0xFFED: ("APP13", "Application segment 13", APP),
    0xFFEE: ("APP14", "Application segment 14", APP),
    0xFFEF: ("APP15", "Application segment 15", APP),
    0xFFF0: ("JPG0", "Extension 0", None),
    0xFFF1: ("JPG1", "Extension 1", None),
    0xFFF2: ("JPG2", "Extension 2", None),
    0xFFF3: ("JPG3", "Extension 3", None),
    0xFFF4: ("JPG4", "Extension 4", None),
    0xFFF5: ("JPG5", "Extension 5", None),
    0xFFF6: ("JPG6", "Extension 6", None),
    0xFFF7: ("JPG7", "Extension 7", None),
    0xFFF8: ("JPG8", "Extension 8", None),
    0xFFF9: ("JPG9", "Extension 9", None),
    0xFFFA: ("JPG10", "Extension 10", None),
    0xFFFB: ("JPG11", "Extension 11", None),
    0xFFFC: ("JPG12", "Extension 12", None),
    0xFFFD: ("JPG13", "Extension 13", None),
    0xFFFE: ("COM", "Comment", COM)
}


def _accept(prefix):
    return prefix[0:1] == b"\377"


class JpegImageFile(ImageFile.ImageFile):

    format = "JPEG"
    format_description = "JPEG (ISO 10918)"

    def _open(self):

        s = self.fp.read(1)

        if i8(s[0]) != 255:
            raise SyntaxError("not a JPEG file")

        self.bits = self.layers = 0

        self.layer = []
        self.huffman_dc = {}
        self.huffman_ac = {}
        self.quantization = {}
        self.app = {}
        self.applist = []
        self.icclist = []

        while True:

            s = s + self.fp.read(1)

            i = i16(s)

            if i in MARKER:
                name, description, handler = MARKER[i]
                if handler is not None:
                    handler(self, i)
                if i == 0xFFDA:
                    rawmode = self.mode
                    if self.mode == "CMYK":
                        rawmode = "CMYK;I"
                    self.tile = [("jpeg", (0,0) + self.size, 0, (rawmode, ""))]
                    break
                s = self.fp.read(1)
            elif i == 0 or i == 65535:
                s = "\xff"
            else:
                raise SyntaxError("no marker found")

    def draft(self, mode, size):

        if len(self.tile) != 1:
            return

        d, e, o, a = self.tile[0]
        scale = 0

        if a[0] == "RGB" and mode in ["L", "YCbCr"]:
            self.mode = mode
            a = mode, ""

        if size:
            scale = max(self.size[0] // size[0], self.size[1] // size[1])
            for s in [8, 4, 2, 1]:
                if scale >= s:
                    break
            e = e[0], e[1], (e[2]-e[0]+s-1)//s+e[0], (e[3]-e[1]+s-1)//s+e[1]
            self.size = ((self.size[0]+s-1)//s, (self.size[1]+s-1)//s)
            scale = s

        self.tile = [(d, e, o, a)]
        self.decoderconfig = (scale, 1)

        return self

    def load_djpeg(self):


        import tempfile, os
        file = tempfile.mktemp()
        os.system("djpeg %s >%s" % (self.filename, file))

        try:
            self.im = Image.core.open_ppm(file)
        finally:
            try: os.unlink(file)
            except: pass

        self.mode = self.im.mode
        self.size = self.im.size

        self.tile = []

    def _getexif(self):
        return _getexif(self)


def _getexif(self):
    from PIL import TiffImagePlugin
    import io
    def fixup(value):
        if len(value) == 1:
            return value[0]
        return value
    try:
        data = self.info["exif"]
    except KeyError:
        return None
    file = io.BytesIO(data[6:])
    head = file.read(8)
    exif = {}
    info = TiffImagePlugin.ImageFileDirectory(head)
    info.load(file)
    for key, value in info.items():
        exif[key] = fixup(value)
    try:
        file.seek(exif[0x8769])
    except KeyError:
        pass
    else:
        info = TiffImagePlugin.ImageFileDirectory(head)
        info.load(file)
        for key, value in info.items():
            exif[key] = fixup(value)
    try:
        file.seek(exif[0x8825])
    except KeyError:
        pass
    else:
        info = TiffImagePlugin.ImageFileDirectory(head)
        info.load(file)
        exif[0x8825] = gps = {}
        for key, value in info.items():
            gps[key] = fixup(value)
    return exif


RAWMODE = {
    "1": "L",
    "L": "L",
    "RGB": "RGB",
    "RGBA": "RGB",
    "RGBX": "RGB",
    "CMYK": "CMYK;I",
    "YCbCr": "YCbCr",
}

zigzag_index = ( 0,  1,  5,  6, 14, 15, 27, 28,
                 2,  4,  7, 13, 16, 26, 29, 42,
                 3,  8, 12, 17, 25, 30, 41, 43,
                 9, 11, 18, 24, 31, 40, 44, 53,
                10, 19, 23, 32, 39, 45, 52, 54,
                20, 22, 33, 38, 46, 51, 55, 60,
                21, 34, 37, 47, 50, 56, 59, 61,
                35, 36, 48, 49, 57, 58, 62, 63)

samplings = {
             (1, 1, 1, 1, 1, 1): 0,
             (2, 1, 1, 1, 1, 1): 1,
             (2, 2, 1, 1, 1, 1): 2,
            }

def convert_dict_qtables(qtables):
    qtables = [qtables[key] for key in xrange(len(qtables)) if qtables.has_key(key)]
    for idx, table in enumerate(qtables):
        qtables[idx] = [table[i] for i in zigzag_index]
    return qtables

def get_sampling(im):
    sampling = im.layer[0][1:3] + im.layer[1][1:3] + im.layer[2][1:3]
    return samplings.get(sampling, -1)

def _save(im, fp, filename):

    try:
        rawmode = RAWMODE[im.mode]
    except KeyError:
        raise IOError("cannot write mode %s as JPEG" % im.mode)

    info = im.encoderinfo

    dpi = info.get("dpi", (0, 0))

    quality = info.get("quality", 0)
    subsampling = info.get("subsampling", -1)
    qtables = info.get("qtables")

    if quality == "keep":
        quality = 0
        subsampling = "keep"
        qtables = "keep"
    elif quality in presets:
        preset = presets[quality]
        quality = 0
        subsampling = preset.get('subsampling', -1)
        qtables = preset.get('quantization')
    elif not isinstance(quality, int):
        raise ValueError("Invalid quality setting")
    else:
        if subsampling in presets:
            subsampling = presets[subsampling].get('subsampling', -1)
        if qtables in presets:
            qtables = presets[qtables].get('quantization')

    if subsampling == "4:4:4":
        subsampling = 0
    elif subsampling == "4:2:2":
        subsampling = 1
    elif subsampling == "4:1:1":
        subsampling = 2
    elif subsampling == "keep":
        if im.format != "JPEG":
            raise ValueError("Cannot use 'keep' when original image is not a JPEG")
        subsampling = get_sampling(im)

    def validate_qtables(qtables):
        if qtables is None:
            return qtables
        if isStringType(qtables):
            try:
                lines = [int(num) for line in qtables.splitlines()
                         for num in line.split('#', 1)[0].split()]
            except ValueError:
                raise ValueError("Invalid quantization table")
            else:
                qtables = [lines[s:s+64] for s in xrange(0, len(lines), 64)]
        if isinstance(qtables, (tuple, list, dict)):
            if isinstance(qtables, dict):
                qtables = convert_dict_qtables(qtables)
            elif isinstance(qtables, tuple):
                qtables = list(qtables)
            if not (0 < len(qtables) < 5):
                raise ValueError("None or too many quantization tables")
            for idx, table in enumerate(qtables):
                try:
                    if len(table) != 64:
                        raise
                    table = array.array('b', table)
                except TypeError:
                    raise ValueError("Invalid quantization table")
                else:
                    qtables[idx] = list(table)
            return qtables

    if qtables == "keep":
        if im.format != "JPEG":
            raise ValueError("Cannot use 'keep' when original image is not a JPEG")
        qtables = getattr(im, "quantization", None)
    qtables = validate_qtables(qtables)

    extra = b""

    icc_profile = info.get("icc_profile")
    if icc_profile:
        ICC_OVERHEAD_LEN = 14
        MAX_BYTES_IN_MARKER = 65533
        MAX_DATA_BYTES_IN_MARKER = MAX_BYTES_IN_MARKER - ICC_OVERHEAD_LEN
        markers = []
        while icc_profile:
            markers.append(icc_profile[:MAX_DATA_BYTES_IN_MARKER])
            icc_profile = icc_profile[MAX_DATA_BYTES_IN_MARKER:]
        i = 1
        for marker in markers:
            size = struct.pack(">H", 2 + ICC_OVERHEAD_LEN + len(marker))
            extra = extra + (b"\xFF\xE2" + size + b"ICC_PROFILE\0" + o8(i) + o8(len(markers)) + marker)
            i = i + 1

    im.encoderconfig = (
        quality,
        "progressive" in info or "progression" in info,
        info.get("smooth", 0),
        "optimize" in info,
        info.get("streamtype", 0),
        dpi[0], dpi[1],
        subsampling,
        qtables,
        extra,
        info.get("exif", b"")
        )


    bufsize=0
    if "optimize" in info or "progressive" in info or "progression" in info:
        bufsize = im.size[0]*im.size[1]

    bufsize = max(ImageFile.MAXBLOCK, bufsize, len(info.get("exif",b"")) + 5 )

    ImageFile._save(im, fp, [("jpeg", (0,0)+im.size, 0, rawmode)], bufsize)

def _save_cjpeg(im, fp, filename):
    import os
    file = im._dump()
    os.system("cjpeg %s >%s" % (file, filename))
    try: os.unlink(file)
    except: pass


Image.register_open("JPEG", JpegImageFile, _accept)
Image.register_save("JPEG", _save)

Image.register_extension("JPEG", ".jfif")
Image.register_extension("JPEG", ".jpe")
Image.register_extension("JPEG", ".jpg")
Image.register_extension("JPEG", ".jpeg")

Image.register_mime("JPEG", "image/jpeg")
