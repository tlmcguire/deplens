

from typing import IO, Any, AnyStr, Union

from lxml.etree import XMLParser as _UnsafeXMLParser
from lxml.etree import parse as _parse


class _XMLParser(_UnsafeXMLParser):
    def __init__(self, *args, **kwargs):
        kwargs['resolve_entities'] = False
        kwargs['no_network'] = True
        super().__init__(*args, **kwargs)


def parse_xml(source: Union[AnyStr, IO[Any]], recover: bool = False):
    """Wrapper around lxml's parse to provide protection against XXE attacks."""

    parser = _XMLParser(recover=recover, remove_pis=False)
    return _parse(source, parser=parser)


__all__ = ['parse_xml']
