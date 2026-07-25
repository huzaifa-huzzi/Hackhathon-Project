from pprint import pprint

from lib.backend.metadata import inspect_metadata

image = "test_images/real_screenshot.png"  # change this

result = inspect_metadata(image)

pprint(result.model_dump(), sort_dicts=False)
