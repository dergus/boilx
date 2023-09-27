package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/AlecAivazis/survey/v2/core"
	"github.com/Masterminds/sprig/v3"
	"github.com/go-git/go-git/v5/plumbing"
	"gopkg.in/yaml.v2"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Masterminds/semver/v3"
	"github.com/antonmedv/expr"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/fatih/color"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/liamg/tml"
	"github.com/samber/lo"
	"github.com/tj/go-spin"
	"github.com/urfave/cli/v2"
)

var currentVersion = semver.New(1, 0, 1, "", "")
var defaultTemplateVersion = semver.New(1, 0, 0, "", "")

var fmtErr = color.New(color.FgHiRed).SprintFunc()
var fmtWarn = color.New(color.FgHiYellow).SprintFunc()
var fmtSuccess = color.New(color.FgHiGreen).SprintFunc()
var fmtInfo = color.New(color.FgHiWhite).SprintFunc()

func printErr(err error) {
	fmt.Println(fmtErr("🛑 " + err.Error()))
}

func printWarn(msg string) {
	fmt.Println(fmtWarn("⚠ ️" + msg))
}

func printSuccess(msg string) {
	fmt.Println(fmtSuccess("✔ ️" + msg))
}

func printInfo(msg string) {
	fmt.Println(fmtInfo("ℹ️ " + msg))
}

func printSpinner(msg string) (cancel func()) {
	// using channel for cancellation instead of context.WithCancel
	// as spinner should be cleaned up after finished
	// but context's cancel func doesn't wait for cancelling to be finished
	cancelChan := make(chan struct{})
	msg = fmtInfo(msg)
	go func() {
		s := spin.New()
		for {
			select {
			case <-cancelChan:
				fmt.Print("\r")
				return
			default:
				fmt.Printf("\r%s %s ", msg, s.Next())
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	return func() {
		select {
		case _, ok := <-cancelChan:
			if !ok {
				return
			}
		default:
			cancelChan <- struct{}{}
			close(cancelChan)
		}
	}
}

func main() {
	app := &cli.App{
		Name:            "boilx",
		Usage:           "create a project from a template",
		Description:     "interactive app boilerplate generation from templates",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:        "create",
				Description: "create new project from a given templates",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "name of new the project (a directory with this name will be created to contain the project files)",
						Required: true,
						Aliases:  []string{"n"},
					},
					&cli.StringFlag{
						Name:     "tmpl",
						Usage:    "url of a remote git repo or path to a directory with the template",
						Required: true,
						Aliases:  []string{"t"},
					},
					&cli.StringFlag{
						Name:    "private",
						Usage:   "is private repository",
						Aliases: []string{"p"},
					},
					&cli.StringFlag{
						Name:    "key_path",
						Usage:   "path to a private key file, for private repos, by default ~/.ssh/id_rsa",
						Aliases: []string{"k"},
					},
					&cli.StringFlag{
						Name:    "key_password",
						Usage:   "private key password if exists",
						Aliases: []string{"w"},
					},
					&cli.StringFlag{
						Name:    "git_branch",
						Usage:   "git branch name (optional)",
						Aliases: []string{"b"},
					},
				},
				Action: createNewApp,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

var appNameRegex = regexp.MustCompile("^[a-zA-Z0-9_-]+$")

const boilxFileName = "boilx.yaml"

func createNewApp(c *cli.Context) error {
	name := c.String("name")

	if !appNameRegex.MatchString(name) {
		return fmt.Errorf("app name can consist only of alphanumeric chars and '_', '-' symbols")
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("can't get current working directory: %w", err)
	}

	_, err = os.Stat(filepath.Join(wd, name))
	if err == nil {
		return fmt.Errorf("directory with nama '%s' already exists in current path", name)
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error reading file system: %w", err)
	}

	tmpl := c.String("tmpl")
	endpoint, err := transport.NewEndpoint(tmpl)
	if err != nil {
		return fmt.Errorf("unknown template endpoint: %w", err)
	}

	isRemoteTmpl := endpoint.Protocol != "file"

	isPrivate := c.Bool("private")
	keyPath := c.String("key_path")
	keyPassword := c.String("key_password")
	gitBranchName := c.String("git_branch")

	var tmplPath string
	if isRemoteTmpl {
		cancelSpinner := printSpinner("🚀 downloading remote git repository with the template")
		defer cancelSpinner()

		if isPrivate && keyPath == "" {
			keyPath, err = getDefaultPrivateKeyPath()
			if err != nil {
				return fmt.Errorf("can't get default private key path: %w", err)
			}
		}

		p, err := downloadGitRepo(c.Context, tmpl, keyPath, keyPassword, gitBranchName)
		if err != nil {
			return fmt.Errorf("can't download template from remote git repo: %w", err)
		}

		defer func() {
			if err = os.RemoveAll(tmplPath); err != nil {
				printErr(fmt.Errorf("couldn't remove temporary directory with template files at %s", tmplPath))
			}
		}()

		cancelSpinner()
		tmplPath = p
		printSuccess("successfully downloaded remote git repository with template")
	} else {
		tmplPath = tmpl
	}

	tmplConf, err := parseTemplateConfig(filepath.Join(tmplPath, boilxFileName))

	if err != nil {
		return fmt.Errorf("can't parse template config: %w", err)
	}

	if err = validateTemplateConfig(tmplConf); err != nil {
		return fmt.Errorf("template config isn't valid: %w", err)
	}

	qs := configParamsToSurveyQs(tmplConf.Params, tmplConf.paramOrder)

	answers := make(ParamValues)
	for _, q := range qs {
		if q.HideRule != nil {
			res, err := expr.Eval(*q.HideRule, answers)
			if err != nil {
				return fmt.Errorf("hide rule for param '%s' returned an error: %w", q.Name, err)
			}

			resBool, ok := res.(bool)
			if !ok {
				return fmt.Errorf("hide rule for param '%s' didn't return a bool value", q.Name)
			}

			if resBool {
				continue
			}
		}

		resp := make(map[string]any)
		sq := &survey.Question{
			Name:     q.Name,
			Prompt:   q.Prompt,
			Validate: q.Validate,
		}

		if err = survey.Ask([]*survey.Question{sq}, &resp); err != nil {
			return fmt.Errorf("something went wrong: %w", err)
		}

		answers[q.Name] = decodeAnswer(resp[q.Name])
	}

	answers["appName"] = name

	dstPath := filepath.Join(wd, name)

	xps, err := getExcludedPaths(tmplConf.PathRules, answers)
	if err != nil {
		return fmt.Errorf("can't get excluded paths: %w", err)
	}
	xps.Add(boilxFileName)
	xps.Add(".git")

	printInfo("creating app from template...")

	srcPath := tmplPath
	if tmplConf.SourcePath != nil {
		srcPath = filepath.Join(tmplPath, *tmplConf.SourcePath)
	}

	if err = processTemplate(srcPath, dstPath, answers, xps, tmplConf.Commands); err != nil {
		return fmt.Errorf("error processing template: %w", err)
	}

	printSuccess("successfully created app from template!")

	return nil
}

func decodeAnswer(answer any) any {
	switch vv := answer.(type) {
	case core.OptionAnswer:
		return vv.Value
	case []survey.OptionAnswer:
		ovs := make([]string, 0, len(vv))
		for _, o := range vv {
			ovs = append(ovs, o.Value)
		}

		return ovs
	}

	return answer
}

//go:generate go run github.com/dmarkham/enumer -type=Kind -text -yaml
type Kind int

const (
	String Kind = iota
	Bool
	Float
	Integer
)

func castKindValue(k Kind, v any) (any, error) {
	switch k {
	case String:
		if _, ok := v.(string); ok {
			return v, nil
		}

		return fmt.Sprint(v), nil
	case Bool:
		switch vv := v.(type) {
		case bool:
			return vv, nil
		case string:
			return strconv.ParseBool(vv)
		}

		return nil, fmt.Errorf("can't cast '%v' to %s", v, k)
	case Float:
		switch vv := v.(type) {
		case float64:
			return vv, nil
		case string:
			return strconv.ParseFloat(vv, 64)
		}

		return nil, fmt.Errorf("can't cast '%v' to %s", v, k)
	case Integer:
		switch vv := v.(type) {
		case int:
			return vv, nil
		case string:
			return strconv.ParseInt(vv, 0, 0)
		}

		return nil, fmt.Errorf("can't cast '%v' to %s", v, k)
	}

	return nil, fmt.Errorf("kind '%s' is not supported", k)
}

type ParamValidation struct {
	Rule        string `yaml:"rule"`
	Description string `yaml:"description"`
}

type ConfigParam struct {
	Kind       Kind             `yaml:"kind"`
	Message    string           `yaml:"message"`
	Help       string           `yaml:"help"`
	Values     []string         `yaml:"values"`
	Default    any              `yaml:"default"`
	Validation *ParamValidation `yaml:"validation"`
	IsMulti    bool             `yaml:"is_multi"`
	IsRequired bool             `yaml:"is_required"`
	IsPassword bool             `yaml:"is_password"`
	HideRule   *string          `yaml:"hide_rule"`
}

type ConfigParams map[string]ConfigParam

type PathRule struct {
	Paths []string `yaml:"paths"`
	Rule  string   `yaml:"rule"`
}

type Commands struct {
	PreInit  []CommandConf `yaml:"pre_init"`
	PostInit []CommandConf `yaml:"post_init"`
}

type CommandConf struct {
	Name string `json:"name"`
	Cmd  string `json:"cmd"`
}

type TemplateConfig struct {
	Version     *string      `yaml:"version"`
	SourcePath  *string      `yaml:"source_path"`
	Description string       `yaml:"description"`
	Params      ConfigParams `yaml:"params"`
	PathRules   []PathRule   `yaml:"path_rules"`
	Commands    Commands     `yaml:"commands"`
	paramOrder  []string
}

func parseTemplateConfig(boilxFilePath string) (*TemplateConfig, error) {
	tc := &TemplateConfig{}

	boilxFile, err := os.ReadFile(boilxFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			printWarn("boilx file wasn't found, proceeding without it")

			return tc, nil
		} else {
			return nil, fmt.Errorf("can't read boilx file: %w", err)
		}
	}

	if err := yaml.Unmarshal(boilxFile, &tc); err != nil {
		return nil, err
	}

	type confParam struct {
		Params yaml.MapSlice `yaml:"params"`
	}

	var cf confParam
	if err := yaml.Unmarshal(boilxFile, &cf); err != nil {
		return nil, err
	}

	for _, item := range cf.Params {
		tc.paramOrder = append(tc.paramOrder, item.Key.(string))
	}

	return tc, nil
}

func validatePath(path string) error {
	if path == "" {
		return errors.New("source path can't be an empty string")
	}

	if path[0] == '/' {
		return errors.New("source path should be relative to config file")
	}

	return nil
}

func validateTemplateConfig(tc *TemplateConfig) error {
	if tc.SourcePath != nil {
		if err := validatePath(*tc.SourcePath); err != nil {
			return err
		}
	}

	tv := defaultTemplateVersion
	if tc.Version != nil {
		var err error
		tv, err = semver.StrictNewVersion(*tc.Version)

		if err != nil {
			return fmt.Errorf("invalid version string '%s', should be SemVer", *tc.Version)
		}
	} else {
		printWarn(fmt.Sprintf("template schema version is not specified, assuming default version (%s)", defaultTemplateVersion))
	}

	if currentVersion.Major() != tv.Major() {
		return fmt.Errorf("BoilX's major version (%d) and the template's major version (%d) do not match", currentVersion.Major(), tv.Major())
	}

	if tv.Minor() > currentVersion.Minor() {
		printWarn(fmt.Sprintf("template's minor version (%d) is greater than BoilX's minor version (%d). Not all functionality might be supported.", tv.Minor(), currentVersion.Minor()))
	}

	for k, p := range tc.Params {
		if p.Message == "" {
			return fmt.Errorf("'%s': message field can't be empty", k)
		}

		if p.HideRule != nil {
			_, err := expr.Compile(*p.HideRule)
			if err != nil {
				return fmt.Errorf("hide rule '%s' is invalid: %w", *p.HideRule, err)
			}
		}

		if v := p.Validation; v != nil {
			_, err := expr.Compile(v.Rule)
			if err != nil {
				return fmt.Errorf("validation rule '%s' is invalid: %w", v.Rule, err)
			}
		}

		for _, v := range p.Values {
			if _, err := castKindValue(p.Kind, v); err != nil {
				return fmt.Errorf("can't cast possible value '%s' to kind '%s'", v, p.Kind)
			}
		}

		if p.Default != nil {
			var defVals []any
			if p.IsMulti {
				if dvs, ok := p.Default.([]any); ok {
					defVals = dvs
				} else {
					return fmt.Errorf("default value of multiselect should be an array")
				}
			} else {
				defVals = []any{p.Default}
			}

			for _, v := range defVals {
				if _, err := castKindValue(p.Kind, v); err != nil {
					return fmt.Errorf("can't cast default value '%s' to kind '%s'", v, p.Kind)
				}
			}
		}
	}

	for _, r := range tc.PathRules {
		for _, p := range r.Paths {
			if err := validatePath(p); err != nil {
				return err
			}
		}

		_, err := expr.Compile(r.Rule)
		if err != nil {
			return fmt.Errorf("path rule '%s' is invalid: %w", r.Rule, err)
		}
	}

	for _, c := range tc.Commands.PreInit {
		if len(c.Name) == 0 {
			return fmt.Errorf("empty name for '%s'", c.Cmd)
		}

		if len(c.Cmd) == 0 {
			return fmt.Errorf("empty cmd for '%s'", c.Name)
		}
	}

	for _, c := range tc.Commands.PostInit {
		if len(c.Name) == 0 {
			return fmt.Errorf("empty name for '%s'", c.Cmd)
		}

		if len(c.Cmd) == 0 {
			return fmt.Errorf("empty cmd for '%s'", c.Name)
		}
	}

	return nil
}

func downloadGitRepo(
	ctx context.Context,
	repoURL string,
	privateKeyPath string,
	privateKeyPassword string,
	branchName string,
) (tmplPath string, err error) {
	tmplDir, err := os.MkdirTemp(os.TempDir(), "boilx_template_*")
	if err != nil {
		return "", fmt.Errorf("can't create directory for downloading template: %w", err)
	}

	var auth transport.AuthMethod
	if privateKeyPath != "" {
		auth, err = ssh.NewPublicKeysFromFile("git", privateKeyPath, privateKeyPassword)
		if err != nil {
			return "", fmt.Errorf("can't get public keys from file: %s", err)
		}
	}

	var refName plumbing.ReferenceName
	if branchName != "" {
		refName = plumbing.NewBranchReferenceName(branchName)
	}

	_, err = git.PlainCloneContext(ctx, tmplDir, false, &git.CloneOptions{
		URL:           repoURL,
		SingleBranch:  true,
		ReferenceName: refName,
		Depth:         1,
		Auth:          auth,
	})

	if err != nil {
		return "", fmt.Errorf("can't download template repo: %w", err)
	}

	return tmplDir, nil
}

type ParamValues map[string]any

const templateFileExt = ".tmpl"

func processTemplate(
	sourcePath string,
	destPath string,
	params ParamValues,
	excludedPaths mapset.Set[string],
	commands Commands,
) (err error) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "boilx_app_*")
	if err != nil {
		return fmt.Errorf("can't create temporary directory for app: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}

		removeErr := os.RemoveAll(tempDir)
		if removeErr != nil {
			printWarn(fmt.Sprintf("couldn't remove temporary directory with template files at %s", tempDir))
		}
	}()

	if err := os.Chmod(tempDir, 0777); err != nil {
		return fmt.Errorf("can't change temp dir mode: %w", err)
	}

	if err := runCommands(commands.PreInit, tempDir, params); err != nil {
		return err
	}

	err = filepath.WalkDir(sourcePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error while visiting path %s: %w", path, err)
		}

		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return fmt.Errorf("can't get relative path for '%s': %w", path, err)
		}

		if relPath == "." {
			return nil
		}

		if excludedPaths.Contains(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		pathTmpl, err := template.New("").Funcs(sprig.FuncMap()).Parse(relPath)

		if err == nil {
			var buf bytes.Buffer
			if err := pathTmpl.Execute(&buf, params); err != nil {
				return fmt.Errorf("can't render path template: path: %s, err %w", relPath, err)
			}

			relPath = buf.String()
		}

		absPath := filepath.Join(tempDir, relPath)

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("can't get info for file '%s': %w", path, err)
		}

		mode := info.Mode()

		if d.IsDir() {
			if err := os.Mkdir(absPath, os.ModeDir); err != nil {
				return fmt.Errorf("can't create directory '%s': %w", absPath, err)
			}

			if err := os.Chmod(absPath, mode); err != nil {
				return fmt.Errorf("can't change mode of '%s': %w", absPath, err)
			}

			return nil
		}

		fd, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("can't read content's of '%s': %w", path, err)
		}

		if filepath.Ext(relPath) == templateFileExt {
			absPath = absPath[:len(absPath)-len(templateFileExt)]

			name := filepath.Base(path)
			tmpl, err := template.New(name).Funcs(sprig.FuncMap()).ParseFiles(path)
			if err != nil {
				return fmt.Errorf("can't parse template '%s': %w", relPath, err)
			}

			var buf bytes.Buffer

			if err := tmpl.Funcs(sprig.FuncMap()).Execute(&buf, params); err != nil {
				return fmt.Errorf("can't exec template '%s': %w", relPath, err)
			}

			fd = buf.Bytes()
		}

		if err := os.WriteFile(absPath, fd, d.Type()); err != nil {
			return fmt.Errorf("can't write file '%s': %w", relPath, err)
		}

		if err := os.Chmod(absPath, mode); err != nil {
			return fmt.Errorf("can't change mode of '%s': %w", absPath, err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := runCommands(commands.PostInit, tempDir, params); err != nil {
		return err
	}

	if err := os.Rename(tempDir, destPath); err != nil {
		return fmt.Errorf("can't move temp dir with app files to destination path: %w", err)
	}

	return nil
}

type SurveyQuestion struct {
	Name     string
	Prompt   survey.Prompt
	Validate survey.Validator
	HideRule *string
}

func configParamsToSurveyQs(params ConfigParams, paramOrder []string) []*SurveyQuestion {
	var qs []*SurveyQuestion
	for _, k := range paramOrder {
		p := params[k]
		var validators []survey.Validator
		if p.IsRequired {
			validators = append(validators, survey.Required)
		}

		validators = append(validators, kindValidator(p.Kind))

		if p.Validation != nil {
			validators = append(validators, exprValidator(*p.Validation))
		}

		q := &SurveyQuestion{
			Name:     k,
			Prompt:   promptForParam(p),
			Validate: survey.ComposeValidators(validators...),
			HideRule: p.HideRule,
		}

		qs = append(qs, q)
	}

	return qs
}

func promptForParam(p ConfigParam) survey.Prompt {
	if p.Kind == Bool {
		dflt := false
		if d, ok := p.Default.(bool); ok {
			dflt = d
		}

		return &survey.Confirm{
			Message: p.Message,
			Default: dflt,
			Help:    p.Help,
		}
	}

	if p.IsPassword {
		return &survey.Password{
			Message: p.Message,
			Help:    p.Help,
		}
	}

	if len(p.Values) != 0 {
		if p.IsMulti {
			dflts := p.Default
			if d, ok := lo.FromAnySlice[string](p.Default.([]any)); ok {
				dflts = d
			}

			return &survey.MultiSelect{
				Message: p.Message,
				Options: p.Values,
				Default: dflts,
				Help:    p.Help,
			}
		}
		return &survey.Select{
			Message: p.Message,
			Options: p.Values,
			Default: p.Default,
			Help:    p.Help,
		}
	}

	dflt := ""
	if p.Default != nil {
		dflt = fmt.Sprint(p.Default)
	}

	return &survey.Input{
		Message: p.Message,
		Default: dflt,
		Help:    p.Help,
	}
}

func getExcludedPaths(pathRules []PathRule, params ParamValues) (mapset.Set[string], error) {
	excludedPaths := mapset.NewSet([]string{}...)

	for _, pr := range pathRules {
		res, err := expr.Eval(pr.Rule, params)
		if err != nil {
			return nil, fmt.Errorf("can't execute rule '%s': %w", pr.Rule, err)
		}

		resBool, ok := res.(bool)
		if !ok {
			return nil, fmt.Errorf("return value of the rule '%s' should be bool", pr.Rule)
		}

		if resBool {
			excludedPaths = excludedPaths.Difference(mapset.NewSet(pr.Paths...))
		} else {
			excludedPaths = excludedPaths.Union(mapset.NewSet(pr.Paths...))
		}
	}

	return excludedPaths, nil
}

func kindValidator(kind Kind) survey.Validator {
	return func(ans interface{}) error {
		switch ansVal := ans.(type) {
		case []survey.OptionAnswer:
			for _, a := range ansVal {
				_, err := castKindValue(kind, a.Value)
				return err
			}
		case survey.OptionAnswer, string:
			_, err := castKindValue(kind, ansVal)
			return err
		default:
			return fmt.Errorf("answer can't be parsed")
		}

		return nil
	}
}

func exprValidator(pv ParamValidation) survey.Validator {
	return func(ans any) error {
		res, err := expr.Eval(pv.Rule, map[string]any{"$v": ans})
		if err != nil {
			return fmt.Errorf("can't validate: internal error: %w", err)
		}

		resBool, ok := res.(bool)
		if !ok {
			return fmt.Errorf("expression should return bool value: internal error")
		}

		if !resBool {
			return errors.New(pv.Description)
		}

		return nil
	}
}

func getDefaultPrivateKeyPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, ".ssh", "id_rsa"), nil
}

func runCommands(cmds []CommandConf, workDir string, params ParamValues) error {
	for _, c := range cmds {
		printInfo(tml.Sprintf("executing command <bold><cyan>%s</cyan></bold>", c.Name))
		output, err := runCommand(c.Cmd, workDir, params)
		if err != nil {
			return errors.New(tml.Sprintf("<bold><cyan>%s</cyan></bold>: %s", c.Name, err))
		}

		if output != "" {
			printInfo(tml.Sprintf("<bold><cyan>%s</cyan></bold>: %s", c.Name, output))
		}
	}

	return nil
}

func runCommand(cmdStr string, workDir string, params ParamValues) (string, error) {
	cmdTempl, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(cmdStr)
	if err != nil {
		return "", fmt.Errorf("can't parse command template: %w", err)
	}

	var buf bytes.Buffer
	if err := cmdTempl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("can't execute command template: %w", err)
	}

	// Split command string into command and arguments
	parts := strings.Fields(buf.String())
	head := parts[0]
	parts = parts[1:]

	cmd := exec.Command(head, parts...)
	cmd.Dir = workDir

	output, err := cmd.CombinedOutput()

	return string(output), err
}
