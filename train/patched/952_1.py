import configparser

class Page:
    def __init__(self, locator_file):
        self.locators = self.__load_locators(locator_file)

    def __load_locators(self, locator_file):
        config = configparser.ConfigParser()
        config.read(locator_file)
        locators = {}

        for section in config.sections():
            for key, value in config.items(section):
                if not self.__is_safe_locator(value):
                    raise ValueError(f"Unsafe locator found: {value}")
                locators[key] = value
        return locators

    def __is_safe_locator(self, locator):
        return isinstance(locator, str) and not any(char in locator for char in [';', '&', '|', '>', '<'])

    def __locator__(self, locator_name: str):
        return self.locators.get(locator_name)
