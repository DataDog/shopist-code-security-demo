from ruamel.yaml import YAML

# introduced line
foo = YAML(typ='unsafe')

def myfunction(arg):
    bar = YAML(typ='base')
