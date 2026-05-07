# Define some dploot consts.

FALSE_POSITIVES = [
    ".",
    "..",
    "desktop.ini",
    "Public",
    "Default",
    "Default User",
    "All Users",
]

# simple class to check for false positives, case insensitive
class FalsePositives(list):
    def __init__(self,
                 false_positives: list[str] = None
    ) -> None:
        if false_positives is None:
            false_positives = FALSE_POSITIVES

        super().__init__(map (lambda x: x.lower(), false_positives))

    def __contains__(self, name):
        return super().__contains__(str(name).lower())

    def __setitem__(self, key, value):
        return super().__setitem__(key,str(value).lower())

    def append(self, element):
        return super().append(str(element).lower())