from __future__ import annotations

import re
from functools import lru_cache
from itertools import chain, count
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

try:
    from lxml import etree
except ImportError:
    etree = None

from fontTools import ttLib
from fontTools.subset.util import _add_method
from fontTools.ttLib.tables.S_V_G_ import SVGDocument


__all__ = ["subset_glyphs"]


GID_RE = re.compile(r"^glyph(\d+)$")

NAMESPACES = {
    "svg": "http://www.w3.org/2000/svg",
    "xlink": "http://www.w3.org/1999/xlink",
}
XLINK_HREF = f'{{{NAMESPACES["xlink"]}}}href'


@lru_cache(maxsize=None)
def xpath(path):
    return etree.XPath(path, namespaces=NAMESPACES)


def group_elements_by_id(tree: etree.Element) -> Dict[str, etree.Element]:
    return {el.attrib["id"]: el for el in xpath("//svg:*[@id]")(tree)}


def parse_css_declarations(style_attr: str) -> Dict[str, str]:
    result = {}
    for declaration in style_attr.split(";"):
        if declaration.count(":") == 1:
            property_name, value = declaration.split(":")
            property_name = property_name.strip()
            result[property_name] = value.strip()
        elif declaration.strip():
            raise ValueError(f"Invalid CSS declaration syntax: {declaration}")
    return result


def iter_referenced_ids(tree: etree.Element) -> Iterator[str]:
    find_svg_elements_with_references = xpath(
        ".//svg:*[ "
        "starts-with(@xlink:href, '#') "
        "or starts-with(@fill, 'url(#') "
        "or starts-with(@clip-path, 'url(#') "
        "or contains(@style, ':url(#') "
        "]",
    )
    for el in chain([tree], find_svg_elements_with_references(tree)):
        ref_id = href_local_target(el)
        if ref_id is not None:
            yield ref_id

        attrs = el.attrib
        if "style" in attrs:
            attrs = {**dict(attrs), **parse_css_declarations(el.attrib["style"])}
        for attr in ("fill", "clip-path"):
            if attr in attrs:
                value = attrs[attr]
                if value.startswith("url(#") and value.endswith(")"):
                    ref_id = value[5:-1]
                    assert ref_id
                    yield ref_id


def closure_element_ids(
    elements: Dict[str, etree.Element], element_ids: Set[str]
) -> None:
    unvisited = element_ids
    while unvisited:
        referenced: Set[str] = set()
        for el_id in unvisited:
            if el_id not in elements:
                continue
            referenced.update(iter_referenced_ids(elements[el_id]))
        referenced -= element_ids
        element_ids.update(referenced)
        unvisited = referenced


def subset_elements(el: etree.Element, retained_ids: Set[str]) -> bool:
    if el.attrib.get("id") in retained_ids:
        return True
    if any([subset_elements(e, retained_ids) for e in el]):
        return True
    assert len(el) == 0
    parent = el.getparent()
    if parent is not None:
        parent.remove(el)
    return False


def remap_glyph_ids(
    svg: etree.Element, glyph_index_map: Dict[int, int]
) -> Dict[str, str]:
    elements = group_elements_by_id(svg)
    id_map = {}
    for el_id, el in elements.items():
        m = GID_RE.match(el_id)
        if not m:
            continue
        old_index = int(m.group(1))
        new_index = glyph_index_map.get(old_index)
        if new_index is not None:
            if old_index == new_index:
                continue
            new_id = f"glyph{new_index}"
        else:
            new_id = f".{el_id}"
            n = count(1)
            while new_id in elements:
                new_id = f"{new_id}.{next(n)}"

        id_map[el_id] = new_id
        el.attrib["id"] = new_id

    return id_map


def href_local_target(el: etree.Element) -> Optional[str]:
    if XLINK_HREF in el.attrib:
        href = el.attrib[XLINK_HREF]
        if href.startswith("#") and len(href) > 1:
            return href[1:]
    return None


def update_glyph_href_links(svg: etree.Element, id_map: Dict[str, str]) -> None:
    for el in xpath(".//svg:*[starts-with(@xlink:href, '#glyph')]")(svg):
        old_id = href_local_target(el)
        assert old_id is not None
        if old_id in id_map:
            new_id = id_map[old_id]
            el.attrib[XLINK_HREF] = f"#{new_id}"


def ranges(ints: Iterable[int]) -> Iterator[Tuple[int, int]]:
    sorted_ints = iter(sorted(set(ints)))
    try:
        start = end = next(sorted_ints)
    except StopIteration:
        return
    for v in sorted_ints:
        if v - 1 == end:
            end = v
        else:
            yield (start, end)
            start = end = v
    yield (start, end)


@_add_method(ttLib.getTableClass("SVG "))
def subset_glyphs(self, s) -> bool:
    if etree is None:
        raise ImportError("No module named 'lxml', required to subset SVG")

    glyph_order: List[str] = s.orig_glyph_order
    rev_orig_glyph_map: Dict[str, int] = s.reverseOrigGlyphMap
    glyph_index_map: Dict[int, int] = s.glyph_index_map

    new_docs: List[SVGDocument] = []
    for doc in self.docList:

        glyphs = {
            glyph_order[i] for i in range(doc.startGlyphID, doc.endGlyphID + 1)
        }.intersection(s.glyphs)
        if not glyphs:
            continue

        svg = etree.fromstring(
            doc.data.encode("utf-8"),
            parser=etree.XMLParser(
                huge_tree=True,
                remove_blank_text=True,
                resolve_entities=False,
            ),
        )

        elements = group_elements_by_id(svg)
        gids = {rev_orig_glyph_map[g] for g in glyphs}
        element_ids = {f"glyph{i}" for i in gids}
        closure_element_ids(elements, element_ids)

        if not subset_elements(svg, element_ids):
            continue

        if not s.options.retain_gids:
            id_map = remap_glyph_ids(svg, glyph_index_map)
            update_glyph_href_links(svg, id_map)

        new_doc = etree.tostring(svg, pretty_print=s.options.pretty_svg).decode("utf-8")

        new_gids = (glyph_index_map[i] for i in gids)
        for start, end in ranges(new_gids):
            new_docs.append(SVGDocument(new_doc, start, end, doc.compressed))

    self.docList = new_docs

    return bool(self.docList)
