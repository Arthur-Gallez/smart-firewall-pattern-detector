from yaml import dump
import random

def patternToYAML(patterns):
    pattern_dict = {}
    for pattern in patterns:
        # pattern_dict[pattern.name] = { # To use when pattern.name are available
        random_name = str(random.randint(0, 1000000))
        pattern_dict[random_name] = {
            'protocols': {},
            'bidirectionnal': False # pattern.is_bidirectionnal()
        }
        if pattern.layer_0:
            pattern_dict[random_name]['protocols'][pattern.layer_0.__class__.__name__] = dict(pattern.layer_0.__dict__())
        if pattern.layer_1:
            pattern_dict[random_name]['protocols'][pattern.layer_1.__class__.__name__] = dict(pattern.layer_1.__dict__())
        if pattern.layer_2:
            pattern_dict[random_name]['protocols'][pattern.layer_2.__class__.__name__] = dict(pattern.layer_2.__dict__())
    
    d = dump(pattern_dict)
    return d