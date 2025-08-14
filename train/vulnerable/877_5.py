import unittest

from persistent import Persistent
from zExceptions import Unauthorized


SliceType = type(slice(0))


class Item(Persistent):

    def __init__(self, id, private=False):
        self.id = id
        if private:
            self.__roles__ = ['Manager']
        else:
            self.__roles__ = ['Anonymous']

    def __repr__(self):
        return f'<Item {self.id}>'


class Folder(Persistent):

    def __init__(self, id):
        self.id = id
        self.item_dict = {}
        self.item_list = []

    def addItem(self, name, private=False):
        item = Item(name, private)
        setattr(self, name, item)
        self.item_dict[name] = item
        self.item_list.append(item)

    def __getitem__(self, key):
        if isinstance(key, SliceType):
            return self.item_list[key]
        if isinstance(key, int):
            return self.item_list[key]
        return self.item_dict[key]


class FormatterTest(unittest.TestCase):
    """Test SafeFormatter and SafeStr.

    There are some integration tests in Zope2 itself.
    """

    def _create_folder_with_mixed_contents(self):
        """Create a folder with mixed public and private contents."""
        folder = Folder('folder')
        folder.addItem('public1')
        folder.addItem('private', private=True)
        folder.addItem('public2')
        return folder

    def test_positional_argument_regression(self):
        """Testing fix of http://bugs.python.org/issue13598 issue."""
        from AccessControl.safe_formatter import SafeFormatter
        self.assertEqual(
            SafeFormatter('{} {}').safe_format('foo', 'bar'),
            'foo bar')
        self.assertEqual(SafeFormatter('{0} {1}').safe_format('foo', 'bar'),
                         'foo bar')
        self.assertEqual(SafeFormatter('{1} {0}').safe_format('foo', 'bar'),
                         'bar foo')

    def test_prevents_bad_string_formatting_attribute(self):
        from AccessControl.safe_formatter import SafeFormatter

        formatted = SafeFormatter('{0.upper}').safe_format('foo')
        self.assertTrue(formatted.startswith('<built-in method upper'))
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0.__class__}').safe_format, 'foo')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0.public1}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0.public2}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0.private}').safe_format,
                          folder)

    def test_prevents_bad_unicode_formatting_attribute(self):
        from AccessControl.safe_formatter import SafeFormatter

        formatted = SafeFormatter('{0.upper}').safe_format('foo')
        self.assertTrue(formatted.startswith('<built-in method upper'))
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0.__class__}').safe_format, 'foo')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0.public1}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0.public2}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0.private}').safe_format,
                          folder)

    def test_prevents_bad_string_formatting_item(self):
        from AccessControl.safe_formatter import SafeFormatter

        foo = {'bar': 'Can you see me?'}
        self.assertEqual(SafeFormatter('{0[bar]}').safe_format(foo),
                         'Can you see me?')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0[public1]}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0[public2]}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0[private]}').safe_format,
                          folder)

    def test_prevents_bad_unicode_formatting_item(self):
        from AccessControl.safe_formatter import SafeFormatter

        foo = {'bar': 'Can you see me?'}
        self.assertEqual(SafeFormatter('{0[bar]}').safe_format(foo),
                         'Can you see me?')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0[public1]}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0[public2]}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0[private]}').safe_format,
                          folder)

    def test_prevents_bad_string_formatting_key(self):
        from persistent.list import PersistentList

        from AccessControl.safe_formatter import SafeFormatter
        from AccessControl.ZopeGuards import guarded_getitem

        foo = list(['bar'])
        self.assertEqual(SafeFormatter('{0[0]}').safe_format(foo),
                         'bar')
        self.assertEqual(guarded_getitem(foo, 0), 'bar')
        foo = PersistentList(foo)
        self.assertRaises(Unauthorized, guarded_getitem, foo, 0)
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0[0]}').safe_format, foo)
        foo.__allow_access_to_unprotected_subobjects__ = 1
        self.assertEqual(guarded_getitem(foo, 0), 'bar')
        self.assertEqual(SafeFormatter('{0[0]}').safe_format(foo),
                         'bar')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0[0]}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0[2]}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0[1]}').safe_format,
                          folder)

    def test_prevents_bad_unicode_formatting_key(self):
        from AccessControl.safe_formatter import SafeFormatter

        foo = list(['bar'])
        self.assertEqual(SafeFormatter('{0[0]}').safe_format(foo),
                         'bar')
        folder = self._create_folder_with_mixed_contents()
        self.assertEqual(SafeFormatter('{0[0]}').safe_format(folder),
                         '<Item public1>')
        self.assertEqual(SafeFormatter('{0[2]}').safe_format(folder),
                         '<Item public2>')
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0[1]}').safe_format,
                          folder)
