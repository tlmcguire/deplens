import setuptools

package_index_html = "<html><body><h1>Package Index</h1><ul><li><a href='https://example.com/package1'>Package 1</a></li><li><a href='https://example.com/package2'>Package 2</a></li></ul></body></html>"

index = setuptools.package_index.PackageIndex()

index.parse(package_index_html)