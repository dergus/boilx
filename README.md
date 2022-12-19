# BoilX - interactive boilerplate generation tool

## Features
BoilX let's you interactively generate project boilerplate from remote templates.

#### Main BoilX features:
- powerful interactive prompts
- conditional file generation
- template rendering

## Installation
### Go install from source 
```bash
go install github.com/dergus/boilx@latest
```

## Usage
### Generate project from a template
```bash
boilx create -n <app_name> -t <template>
```
- `-n` - name of the project being generated. A directory with this name will be created in the current working directory to contain project files.
- `-t` - url of a remote git repository or path in local directory with template.

#### Optional parameters
- `-p` - indicates that remote repo with a template is private, default value is false
- `-k` - path to private ssh key, by default `~/.ssh/id_rsa`
- `-w` - private key password, if set

`boilx -h` can be called for help output.

## Creating new templates
BoilX can generate new project from any remote git repository or local folder with files.
But in order to use it's full-power a `boilx.yml` should exist at template root.
Boilx file consists of following sections:
- `source_path` - path to a directory with template files, relative to `boilx` file, default is template root directory
- `params` - a list of parameters that can be used for rendering template files or deciding which files to generate. User will be interactively presented with this params to provide values.
- `path_rules` - contains rules for conditional file generation. If a path is in one of rules it will be generated only if the latest rule it is in is true.

Below is an example of a complete `boilx` file with comments:
```yaml
source_path: "." # path to a directory with template files, relative to boilx file, default is template root directory
params: # a list of parameters that can be used for rendering template files or deciding which files to generate. User will be interactively presented with this params to provide values.
  databases: # name of parameter
    kind: string # parameter type, can be one of string, bool, float, integer
    message: "app databases" # a short description of param
    values: # limit possible values to choose from
      - mysql
      - postgres
    is_multi: true # more than value can be chosen
    default: # default value if user doesn't chose anything
      - mysql
  mysql_dsn:
    kind: string
    message: "mysql connection dsn"
    hide_rule: "'mysql' not in databases" # don't ask for param value from user if expr returns tru
  postgres_dsn:
    kind: string
    message: "postgresql connection dsn"
    hide_rule: "'postgres' not in databases"
  password_salt:
    kind: string
    message: "password salt"
    is_password: true # hide user input
    is_required: true # required value
  is_secret:
    kind: bool
    message: "is a secret project"
  request_rate_limit:
    kind: integer
    message: "maximum number of RPS allowed"
    default: 500
path_rules: # this section contains rules for paths to be generated. If path is in one of rules it will be generated only if the latest rule it is in is true.
  - rule: "'mysql' in databases" # an expression which should return true in order for path to be included in generated project. Param values can be used here.
    paths: # list of paths that are dependent on this rule, same path can be included in several path rules. Paths evaluated in order described here so if path is included or not depends on the result of the latest executed rule with that path.
      - pkg/mysql
  - rule: "'postgres' in databases"
    paths:
      - pkg/postgres
```

All sections of the `boilx` file, as the `boilx` file itself are optional. 

### Template rendering
BoilX will render files with `.tmpl` extension using Go's built-in template engine.
The generated file name will be stripped out of `.tmpl` extension (e.g. `config.yml.tmpl` will be generated as `config.yml`)

### Expression language
All expressions in `BoilX` file are evaluated using https://github.com/antonmedv/expr.
Expression language definition can be found at https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md.