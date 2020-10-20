import json

configuration_filename = "config.json"

open(configuration_filename, 'w+').write(json.dumps({}))
