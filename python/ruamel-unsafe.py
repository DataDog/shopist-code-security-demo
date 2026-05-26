from ruamel.yaml import YAML

foo = YAML(typ='unsafe')

def myfunction(arg):
    bar = YAML(typ='base')
