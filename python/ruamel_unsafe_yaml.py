from ruamel.yaml import YAML

# introduced line
foo = YAML(typ='unsafe')

# introduced line
def myfunction(arg):
    bar = YAML(typ='base')
