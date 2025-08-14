
"""BSON (Binary JSON) encoding and decoding.
"""

import calendar
import datetime
import re
import struct
import sys

from bson.binary import (Binary, OLD_UUID_SUBTYPE,
                         JAVA_LEGACY, CSHARP_LEGACY)
from bson.code import Code
from bson.dbref import DBRef
from bson.errors import (InvalidBSON,
                         InvalidDocument,
                         InvalidStringData)
from bson.max_key import MaxKey
from bson.min_key import MinKey
from bson.objectid import ObjectId
from bson.py3compat import b, binary_type
from bson.son import SON, RE_TYPE
from bson.timestamp import Timestamp
from bson.tz_util import utc


try:
    from bson import _cbson
    _use_c = True
except ImportError:
    _use_c = False

try:
    import uuid
    _use_uuid = True
except ImportError:
    _use_uuid = False

PY3 = sys.version_info[0] == 3


MAX_INT32 = 2147483647
MIN_INT32 = -2147483648
MAX_INT64 = 9223372036854775807
MIN_INT64 = -9223372036854775808

EPOCH_AWARE = datetime.datetime.fromtimestamp(0, utc)
EPOCH_NAIVE = datetime.datetime.utcfromtimestamp(0)

EMPTY = b("")
ZERO  = b("\x00")
ONE   = b("\x01")

BSONNUM = b("\x01")
BSONSTR = b("\x02")
BSONOBJ = b("\x03")
BSONARR = b("\x04")
BSONBIN = b("\x05")
BSONUND = b("\x06")
BSONOID = b("\x07")
BSONBOO = b("\x08")
BSONDAT = b("\x09")
BSONNUL = b("\x0A")
BSONRGX = b("\x0B")
BSONREF = b("\x0C")
BSONCOD = b("\x0D")
BSONSYM = b("\x0E")
BSONCWS = b("\x0F")
BSONINT = b("\x10")
BSONTIM = b("\x11")
BSONLON = b("\x12")
BSONMIN = b("\xFF")
BSONMAX = b("\x7F")


def _get_int(data, position, as_class=None,
             tz_aware=False, uuid_subtype=OLD_UUID_SUBTYPE, unsigned=False):
    format = unsigned and "I" or "i"
    try:
        value = struct.unpack("<%s" % format, data[position:position + 4])[0]
    except struct.error:
        raise InvalidBSON()
    position += 4
    return value, position


def _get_c_string(data, position, length=None):
    if length is None:
        try:
            end = data.index(ZERO, position)
        except ValueError:
            raise InvalidBSON()
    else:
        end = position + length
    value = data[position:end].decode("utf-8")
    position = end + 1

    return value, position


def _make_c_string(string, check_null=False):
    if isinstance(string, unicode):
        if check_null and "\x00" in string:
            raise InvalidDocument("BSON keys / regex patterns must not "
                                  "contain a NULL character")
        return string.encode("utf-8") + ZERO
    else:
        if check_null and ZERO in string:
            raise InvalidDocument("BSON keys / regex patterns must not "
                                  "contain a NULL character")
        try:
            string.decode("utf-8")
            return string + ZERO
        except UnicodeError:
            raise InvalidStringData("strings in documents must be valid "
                                    "UTF-8: %r" % string)


def _get_number(data, position, as_class, tz_aware, uuid_subtype):
    num = struct.unpack("<d", data[position:position + 8])[0]
    position += 8
    return num, position


def _get_string(data, position, as_class, tz_aware, uuid_subtype):
    length = struct.unpack("<i", data[position:position + 4])[0] - 1
    position += 4
    return _get_c_string(data, position, length)


def _get_object(data, position, as_class, tz_aware, uuid_subtype):
    obj_size = struct.unpack("<i", data[position:position + 4])[0]
    encoded = data[position + 4:position + obj_size - 1]
    object = _elements_to_dict(encoded, as_class, tz_aware, uuid_subtype)
    position += obj_size
    if "$ref" in object:
        return (DBRef(object.pop("$ref"), object.pop("$id"),
                      object.pop("$db", None), object), position)
    return object, position


def _get_array(data, position, as_class, tz_aware, uuid_subtype):
    obj, position = _get_object(data, position,
                                as_class, tz_aware, uuid_subtype)
    result = []
    i = 0
    while True:
        try:
            result.append(obj[str(i)])
            i += 1
        except KeyError:
            break
    return result, position


def _get_binary(data, position, as_class, tz_aware, uuid_subtype):
    length, position = _get_int(data, position)
    subtype = ord(data[position:position + 1])
    position += 1
    if subtype == 2:
        length2, position = _get_int(data, position)
        if length2 != length - 4:
            raise InvalidBSON("invalid binary (st 2) - lengths don't match!")
        length = length2
    if subtype in (3, 4) and _use_uuid:
        if uuid_subtype == JAVA_LEGACY:
            java = data[position:position + length]
            value = uuid.UUID(bytes=java[0:8][::-1] + java[8:16][::-1])
        elif uuid_subtype == CSHARP_LEGACY:
            value = uuid.UUID(bytes_le=data[position:position + length])
        else:
            value = uuid.UUID(bytes=data[position:position + length])
        position += length
        return (value, position)
    if PY3 and subtype == 0:
        value = data[position:position + length]
    else:
        value = Binary(data[position:position + length], subtype)
    position += length
    return value, position


def _get_oid(data, position, as_class=None,
             tz_aware=False, uuid_subtype=OLD_UUID_SUBTYPE):
    value = ObjectId(data[position:position + 12])
    position += 12
    return value, position


def _get_boolean(data, position, as_class, tz_aware, uuid_subtype):
    value = data[position:position + 1] == ONE
    position += 1
    return value, position


def _get_date(data, position, as_class, tz_aware, uuid_subtype):
    millis = struct.unpack("<q", data[position:position + 8])[0]
    diff = millis % 1000
    seconds = (millis - diff) / 1000
    position += 8
    if tz_aware:
        dt = EPOCH_AWARE + datetime.timedelta(seconds=seconds)
    else:
        dt = EPOCH_NAIVE + datetime.timedelta(seconds=seconds)
    return dt.replace(microsecond=diff * 1000), position


def _get_code(data, position, as_class, tz_aware, uuid_subtype):
    code, position = _get_string(data, position,
                                 as_class, tz_aware, uuid_subtype)
    return Code(code), position


def _get_code_w_scope(data, position, as_class, tz_aware, uuid_subtype):
    _, position = _get_int(data, position)
    code, position = _get_string(data, position,
                                 as_class, tz_aware, uuid_subtype)
    scope, position = _get_object(data, position,
                                  as_class, tz_aware, uuid_subtype)
    return Code(code, scope), position


def _get_null(data, position, as_class, tz_aware, uuid_subtype):
    return None, position


def _get_regex(data, position, as_class, tz_aware, uuid_subtype):
    pattern, position = _get_c_string(data, position)
    bson_flags, position = _get_c_string(data, position)
    flags = 0
    if "i" in bson_flags:
        flags |= re.IGNORECASE
    if "l" in bson_flags:
        flags |= re.LOCALE
    if "m" in bson_flags:
        flags |= re.MULTILINE
    if "s" in bson_flags:
        flags |= re.DOTALL
    if "u" in bson_flags:
        flags |= re.UNICODE
    if "x" in bson_flags:
        flags |= re.VERBOSE
    return re.compile(pattern, flags), position


def _get_ref(data, position, as_class, tz_aware, uuid_subtype):
    position += 4
    collection, position = _get_c_string(data, position)
    oid, position = _get_oid(data, position)
    return DBRef(collection, oid), position


def _get_timestamp(data, position, as_class, tz_aware, uuid_subtype):
    inc, position = _get_int(data, position, unsigned=True)
    timestamp, position = _get_int(data, position, unsigned=True)
    return Timestamp(timestamp, inc), position


def _get_long(data, position, as_class, tz_aware, uuid_subtype):
    value = long(struct.unpack("<q", data[position:position + 8])[0])
    position += 8
    return value, position


_element_getter = {
    BSONNUM: _get_number,
    BSONSTR: _get_string,
    BSONOBJ: _get_object,
    BSONARR: _get_array,
    BSONBIN: _get_binary,
    BSONUND: _get_null,
    BSONOID: _get_oid,
    BSONBOO: _get_boolean,
    BSONDAT: _get_date,
    BSONNUL: _get_null,
    BSONRGX: _get_regex,
    BSONREF: _get_ref,
    BSONCOD: _get_code,
    BSONSYM: _get_string,
    BSONCWS: _get_code_w_scope,
    BSONINT: _get_int,
    BSONTIM: _get_timestamp,
    BSONLON: _get_long,
    BSONMIN: lambda v, w, x, y, z: (MinKey(), w),
    BSONMAX: lambda v, w, x, y, z: (MaxKey(), w)}


def _element_to_dict(data, position, as_class, tz_aware, uuid_subtype):
    element_type = data[position:position + 1]
    position += 1
    element_name, position = _get_c_string(data, position)
    value, position = _element_getter[element_type](data, position, as_class,
                                                    tz_aware, uuid_subtype)
    return element_name, value, position


def _elements_to_dict(data, as_class, tz_aware, uuid_subtype):
    result = as_class()
    position = 0
    end = len(data) - 1
    while position < end:
        (key, value, position) = _element_to_dict(data, position, as_class,
                                                  tz_aware, uuid_subtype)
        result[key] = value
    return result

def _bson_to_dict(data, as_class, tz_aware, uuid_subtype):
    obj_size = struct.unpack("<i", data[:4])[0]
    length = len(data)
    if length < obj_size:
        raise InvalidBSON("objsize too large")
    if obj_size != length or data[obj_size - 1:obj_size] != ZERO:
        raise InvalidBSON("bad eoo")
    elements = data[4:obj_size - 1]
    return (_elements_to_dict(elements, as_class,
                              tz_aware, uuid_subtype), data[obj_size:])
if _use_c:
    _bson_to_dict = _cbson._bson_to_dict


def _element_to_bson(key, value, check_keys, uuid_subtype):
    if not isinstance(key, basestring):
        raise InvalidDocument("documents must have only string keys, "
                              "key was %r" % key)

    if check_keys:
        if key.startswith("$"):
            raise InvalidDocument("key %r must not start with '$'" % key)
        if "." in key:
            raise InvalidDocument("key %r must not contain '.'" % key)

    name = _make_c_string(key, True)
    if isinstance(value, float):
        return BSONNUM + name + struct.pack("<d", value)

    if _use_uuid:
        if isinstance(value, uuid.UUID):
            if uuid_subtype == JAVA_LEGACY:
                from_uuid = binary_type(value.bytes)
                as_legacy_java = from_uuid[0:8][::-1] + from_uuid[8:16][::-1]
                value = Binary(as_legacy_java, subtype=OLD_UUID_SUBTYPE)
            elif uuid_subtype == CSHARP_LEGACY:
                value = Binary(binary_type(value.bytes_le),
                               subtype=OLD_UUID_SUBTYPE)
            else:
                value = Binary(binary_type(value.bytes), subtype=uuid_subtype)

    if isinstance(value, Binary):
        subtype = value.subtype
        if subtype == 2:
            value = struct.pack("<i", len(value)) + value
        return (BSONBIN + name +
                struct.pack("<i", len(value)) + b(chr(subtype)) + value)
    if isinstance(value, Code):
        cstring = _make_c_string(value)
        if not value.scope:
            length = struct.pack("<i", len(cstring))
            return BSONCOD + name + length + cstring
        scope = _dict_to_bson(value.scope, False, uuid_subtype, False)
        full_length = struct.pack("<i", 8 + len(cstring) + len(scope))
        length = struct.pack("<i", len(cstring))
        return BSONCWS + name + full_length + length + cstring + scope
    if isinstance(value, binary_type):
        if PY3:
            return (BSONBIN + name +
                    struct.pack("<i", len(value)) + ZERO + value)
        cstring = _make_c_string(value)
        length = struct.pack("<i", len(cstring))
        return BSONSTR + name + length + cstring
    if isinstance(value, unicode):
        cstring = _make_c_string(value)
        length = struct.pack("<i", len(cstring))
        return BSONSTR + name + length + cstring
    if isinstance(value, dict):
        return BSONOBJ + name + _dict_to_bson(value, check_keys, uuid_subtype, False)
    if isinstance(value, (list, tuple)):
        as_dict = SON(zip([str(i) for i in range(len(value))], value))
        return BSONARR + name + _dict_to_bson(as_dict, check_keys, uuid_subtype, False)
    if isinstance(value, ObjectId):
        return BSONOID + name + value.binary
    if value is True:
        return BSONBOO + name + ONE
    if value is False:
        return BSONBOO + name + ZERO
    if isinstance(value, int):
        if value > MAX_INT64 or value < MIN_INT64:
            raise OverflowError("BSON can only handle up to 8-byte ints")
        if value > MAX_INT32 or value < MIN_INT32:
            return BSONLON + name + struct.pack("<q", value)
        return BSONINT + name + struct.pack("<i", value)
    if isinstance(value, long):
        if value > MAX_INT64 or value < MIN_INT64:
            raise OverflowError("BSON can only handle up to 8-byte ints")
        return BSONLON + name + struct.pack("<q", value)
    if isinstance(value, datetime.datetime):
        if value.utcoffset() is not None:
            value = value - value.utcoffset()
        millis = int(calendar.timegm(value.timetuple()) * 1000 +
                     value.microsecond / 1000)
        return BSONDAT + name + struct.pack("<q", millis)
    if isinstance(value, Timestamp):
        time = struct.pack("<I", value.time)
        inc = struct.pack("<I", value.inc)
        return BSONTIM + name + inc + time
    if value is None:
        return BSONNUL + name
    if isinstance(value, RE_TYPE):
        pattern = value.pattern
        flags = ""
        if value.flags & re.IGNORECASE:
            flags += "i"
        if value.flags & re.LOCALE:
            flags += "l"
        if value.flags & re.MULTILINE:
            flags += "m"
        if value.flags & re.DOTALL:
            flags += "s"
        if value.flags & re.UNICODE:
            flags += "u"
        if value.flags & re.VERBOSE:
            flags += "x"
        return BSONRGX + name + _make_c_string(pattern, True) + \
            _make_c_string(flags)
    if isinstance(value, DBRef):
        return _element_to_bson(key, value.as_doc(), False, uuid_subtype)
    if isinstance(value, MinKey):
        return BSONMIN + name
    if isinstance(value, MaxKey):
        return BSONMAX + name

    raise InvalidDocument("cannot convert value of type %s to bson" %
                          type(value))


def _dict_to_bson(dict, check_keys, uuid_subtype, top_level=True):
    try:
        elements = []
        if top_level and "_id" in dict:
            elements.append(_element_to_bson("_id", dict["_id"], False, uuid_subtype))
        for (key, value) in dict.iteritems():
            if not top_level or key != "_id":
                elements.append(_element_to_bson(key, value, check_keys, uuid_subtype))
    except AttributeError:
        raise TypeError("encoder expected a mapping type but got: %r" % dict)

    encoded = EMPTY.join(elements)
    length = len(encoded) + 5
    return struct.pack("<i", length) + encoded + ZERO
if _use_c:
    _dict_to_bson = _cbson._dict_to_bson



def decode_all(data, as_class=dict,
               tz_aware=True, uuid_subtype=OLD_UUID_SUBTYPE):
    """Decode BSON data to multiple documents.

    `data` must be a string of concatenated, valid, BSON-encoded
    documents.

    :Parameters:
      - `data`: BSON data
      - `as_class` (optional): the class to use for the resulting
        documents
      - `tz_aware` (optional): if ``True``, return timezone-aware
        :class:`~datetime.datetime` instances

    .. versionadded:: 1.9
    """
    docs = []
    position = 0
    end = len(data) - 1
    while position < end:
        obj_size = struct.unpack("<i", data[position:position + 4])[0]
        if len(data) - position < obj_size:
            raise InvalidBSON("objsize too large")
        if data[position + obj_size - 1:position + obj_size] != ZERO:
            raise InvalidBSON("bad eoo")
        elements = data[position + 4:position + obj_size - 1]
        position += obj_size
        docs.append(_elements_to_dict(elements, as_class,
                                      tz_aware, uuid_subtype))
    return docs
if _use_c:
    decode_all = _cbson.decode_all


def is_valid(bson):
    """Check that the given string represents valid :class:`BSON` data.

    Raises :class:`TypeError` if `bson` is not an instance of
    :class:`str` (:class:`bytes` in python 3). Returns ``True``
    if `bson` is valid :class:`BSON`, ``False`` otherwise.

    :Parameters:
      - `bson`: the data to be validated
    """
    if not isinstance(bson, binary_type):
        raise TypeError("BSON data must be an instance "
                        "of a subclass of %s" % (binary_type.__name__,))

    try:
        (_, remainder) = _bson_to_dict(bson, dict, True, OLD_UUID_SUBTYPE)
        return remainder == EMPTY
    except:
        return False


class BSON(binary_type):
    """BSON (Binary JSON) data.
    """

    @classmethod
    def encode(cls, document, check_keys=False, uuid_subtype=OLD_UUID_SUBTYPE):
        """Encode a document to a new :class:`BSON` instance.

        A document can be any mapping type (like :class:`dict`).

        Raises :class:`TypeError` if `document` is not a mapping type,
        or contains keys that are not instances of
        :class:`basestring` (:class:`str` in python 3). Raises
        :class:`~bson.errors.InvalidDocument` if `document` cannot be
        converted to :class:`BSON`.

        :Parameters:
          - `document`: mapping type representing a document
          - `check_keys` (optional): check if keys start with '$' or
            contain '.', raising :class:`~bson.errors.InvalidDocument` in
            either case

        .. versionadded:: 1.9
        """
        return cls(_dict_to_bson(document, check_keys, uuid_subtype))

    def decode(self, as_class=dict,
               tz_aware=False, uuid_subtype=OLD_UUID_SUBTYPE):
        """Decode this BSON data.

        The default type to use for the resultant document is
        :class:`dict`. Any other class that supports
        :meth:`__setitem__` can be used instead by passing it as the
        `as_class` parameter.

        If `tz_aware` is ``True`` (recommended), any
        :class:`~datetime.datetime` instances returned will be
        timezone-aware, with their timezone set to
        :attr:`bson.tz_util.utc`. Otherwise (default), all
        :class:`~datetime.datetime` instances will be naive (but
        contain UTC).

        :Parameters:
          - `as_class` (optional): the class to use for the resulting
            document
          - `tz_aware` (optional): if ``True``, return timezone-aware
            :class:`~datetime.datetime` instances

        .. versionadded:: 1.9
        """
        (document, _) = _bson_to_dict(self, as_class, tz_aware, uuid_subtype)
        return document


def has_c():
    """Is the C extension installed?

    .. versionadded:: 1.9
    """
    return _use_c


def has_uuid():
    """Is the uuid module available?

    .. versionadded:: 2.3
    """
    return _use_uuid
