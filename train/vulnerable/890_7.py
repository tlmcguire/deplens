from ..expression import getEngine
from . import testHTMLTests


class ChameleonAqPageTemplate(testHTMLTests.AqPageTemplate):
    def pt_getEngine(self):
        return getEngine()


class ChameleonTalesExpressionTests(testHTMLTests.HTMLTests):
    def setUp(self):
        super().setUp()
        self.folder.laf = ChameleonAqPageTemplate()
        self.folder.t = ChameleonAqPageTemplate()

    PREFIX = "CH_"
