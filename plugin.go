package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type (
	// Config holds input parameters for the plugin
	Config struct {
		Actions          []string
		Vars             map[string]string
		Secrets          map[string]string
		InitOptions      InitOptions
		FmtOptions       FmtOptions
		Assertions       Assertions
		Cacert           string
		Sensitive        bool
		RoleARN          string
		RootDir          string
		Parallelism      int
		Targets          []string
		VarFiles         []string
		TerraformDataDir string
	}

	// Netrc is credentials for cloning
	Netrc struct {
		Machine  string
		Login    string
		Password string
	}

	// InitOptions include options for the Terraform's init command
	InitOptions struct {
		BackendConfig []string `json:"backend-config"`
		Lock          *bool    `json:"lock"`
		LockTimeout   string   `json:"lock-timeout"`
	}

	// FmtOptions fmt options for the Terraform's fmt command
	FmtOptions struct {
		List  *bool `json:"list"`
		Write *bool `json:"write"`
		Diff  *bool `json:"diff"`
		Check *bool `json:"check"`
	}

	// Assertions will check number of expected additions, changes and deletions after terraform plan
	Assertions struct {
		AdditionsExact int `json:"additions_exact"`
		ChangesExact   int `json:"changes_exact"`
		DeletionsExact int `json:"deletions_exact"`
	}

	// Plugin represents the plugin instance to be executed
	Plugin struct {
		Config     Config
		Netrc      Netrc
		Terraform  Terraform
	}
)

// Exec executes the plugin
func (p Plugin) Exec() error {
	// Install specified version of terraform
	if p.Terraform.Version != "" {
		err := installTerraform(p.Terraform.Version)

		if err != nil {
			return err
		}
	}

	if p.Config.RoleARN != "" {
		assumeRole(p.Config.RoleARN)
	}

	// writing the .netrc file with Github credentials in it.
	err := writeNetrc(p.Netrc.Machine, p.Netrc.Login, p.Netrc.Password)
	if err != nil {
		return err
	}

	var terraformDataDir string = ".terraform"
	if p.Config.TerraformDataDir != "" {
		terraformDataDir = p.Config.TerraformDataDir
		os.Setenv("TF_DATA_DIR", p.Config.TerraformDataDir)
	}

	var commands []*exec.Cmd

	commands = append(commands, exec.Command("terraform", "version"))

	CopyTfEnv()

	if p.Config.Cacert != "" {
		commands = append(commands, installCaCert(p.Config.Cacert))
	}

	commands = append(commands, deleteCache(terraformDataDir))
	commands = append(commands, initCommand(p.Config.InitOptions))
	commands = append(commands, getModules())

	// Add commands listed from Actions
	for _, action := range p.Config.Actions {
		switch action {
		case "fmt":
			commands = append(commands, tfFmt(p.Config))
		case "validate":
			commands = append(commands, tfValidate(p.Config))
		case "plan":
			commands = append(commands, tfPlan(p.Config, false))
		case "plan-destroy":
			commands = append(commands, tfPlan(p.Config, true))
		case "apply":
			commands = append(commands, tfApply(p.Config))
		case "destroy":
			commands = append(commands, tfDestroy(p.Config))
		default:
			return fmt.Errorf("valid actions are: fmt, validate, plan, apply, plan-destroy, destroy.  You provided %s", action)
		}
	}

	commands = append(commands, deleteCache(terraformDataDir))

	for _, c := range commands {
		if c.Dir == "" {
			wd, err := os.Getwd()
			if err == nil {
				c.Dir = wd
			}
		}
		if p.Config.RootDir != "" {
			c.Dir = c.Dir + "/" + p.Config.RootDir
		}
		if !p.Config.Sensitive {
			trace(c)
		}

		// Directly pass strerr to standard
		c.Stderr = os.Stderr

		// Capture stdout to use for assertions
		var stdout []byte
		var errStdout error
		stdoutIn, _ := c.StdoutPipe()

		err := c.Start()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to execute a command")
		}

		// cmd.Wait() should be called only after we finish reading
		// from stdoutIn and stderrIn.
		// wg ensures that we finish
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			stdout, errStdout = copyAndCapture(os.Stdout, stdoutIn)
			wg.Done()
		}()
		wg.Wait()

		err = c.Wait()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to run a command")
		}
		if errStdout != nil {
			logrus.WithFields(logrus.Fields{
				"error": errStdout,
			}).Fatal("Failed to capture stdout or stderr")
		}

		// Evaluate assertions only when running terraform plan
		if c.Args[1] == "plan" {
			p.evaluateAssertions(string(stdout))
		}

		logrus.Debug("Command completed successfully")
	}

	return nil
}

func (p Plugin) evaluateAssertions(planOutput string) {
	var additions = 0
	var changes = 0
	var deletions = 0

	updateToDateRe := regexp.MustCompile(`No changes\. Infrastructure is up-to-date\.`)
	if !updateToDateRe.MatchString(planOutput) {
		// Check if assertions are met based on "Plan: X to add, X to change, X to destroy." in output
		planRe := regexp.MustCompile(`(?P<Additions>[0-9]+) to add, (?P<Changes>[0-9]+) to change, (?P<Deletions>[0-9]+) to destroy\.`)
		matches := planRe.FindStringSubmatch(planOutput)
		if len(matches) != 4 {
			logrus.Fatal("Unexpected number of matches in terraform output when evaluating assertions")
		}

		additions, _ = strconv.Atoi(matches[1])
		changes, _ = strconv.Atoi(matches[2])
		deletions, _ = strconv.Atoi(matches[3])
	}

	if p.Config.Assertions.AdditionsExact > -1 {
		if additions != p.Config.Assertions.AdditionsExact {
			logrus.Fatal(fmt.Sprintf("FATAL: Expected %d additions but saw %d additions on terraform plan", p.Config.Assertions.AdditionsExact, additions))
		} else {
			fmt.Println(fmt.Sprintf("INFO: As expected saw %d additions on terraform plan.", additions))
		}
	}

	if p.Config.Assertions.ChangesExact > -1 {
		if changes != p.Config.Assertions.ChangesExact {
			logrus.Fatal(fmt.Sprintf("FATAL: Expected %d changes but saw %d changes on terraform plan", p.Config.Assertions.ChangesExact, changes))
		} else {
			fmt.Println(fmt.Sprintf("INFO: As expected saw %d changes on terraform plan.", changes))
		}
	}

	if p.Config.Assertions.DeletionsExact > -1 {
		if deletions != p.Config.Assertions.DeletionsExact {
			logrus.Fatal(fmt.Sprintf("FATAL: Expected %d deletions but saw %d deletions on terraform plan", p.Config.Assertions.DeletionsExact, deletions))
		} else {
			fmt.Println(fmt.Sprintf("INFO: As expected saw %d deletions on terraform plan.", deletions))
		}
	}
}

func copyAndCapture(w io.Writer, r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1024, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			out = append(out, d...)
			_, err := w.Write(d)
			if err != nil {
				return out, err
			}
		}
		if err != nil {
			// Read returns io.EOF at the end of file, which is not an error for us
			if err == io.EOF {
				err = nil
			}
			return out, err
		}
	}
}

// CopyTfEnv creates copies of TF_VAR_ to lowercase
func CopyTfEnv() {
	tfVar := regexp.MustCompile(`^TF_VAR_.*$`)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if tfVar.MatchString(pair[0]) {
			name := strings.Split(pair[0], "TF_VAR_")
			os.Setenv(fmt.Sprintf("TF_VAR_%s", strings.ToLower(name[1])), pair[1])
		}
	}
}

func assumeRole(roleArn string) {
	client := sts.New(session.New())
	duration := time.Hour * 1
	stsProvider := &stscreds.AssumeRoleProvider{
		Client:          client,
		Duration:        duration,
		RoleARN:         roleArn,
		RoleSessionName: "drone",
	}

	value, err := credentials.NewCredentials(stsProvider).Get()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Error assuming role!")
	}
	os.Setenv("AWS_ACCESS_KEY_ID", value.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", value.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", value.SessionToken)
}

func deleteCache(terraformDataDir string) *exec.Cmd {
	return exec.Command(
		"rm",
		"-rf",
		terraformDataDir,
	)
}

func getModules() *exec.Cmd {
	return exec.Command(
		"terraform",
		"get",
	)
}

func initCommand(config InitOptions) *exec.Cmd {
	args := []string{
		"init",
	}

	for _, v := range config.BackendConfig {
		args = append(args, fmt.Sprintf("-backend-config=%s", v))
	}

	// True is default in TF
	if config.Lock != nil {
		args = append(args, fmt.Sprintf("-lock=%t", *config.Lock))
	}

	// "0s" is default in TF
	if config.LockTimeout != "" {
		args = append(args, fmt.Sprintf("-lock-timeout=%s", config.LockTimeout))
	}

	// Fail Terraform execution on prompt
	args = append(args, "-input=false")

	return exec.Command(
		"terraform",
		args...,
	)
}

func installCaCert(cacert string) *exec.Cmd {
	ioutil.WriteFile("/usr/local/share/ca-certificates/ca_cert.crt", []byte(cacert), 0644)
	return exec.Command(
		"update-ca-certificates",
	)
}

func trace(cmd *exec.Cmd) {
	fmt.Println("$", strings.Join(cmd.Args, " "))
}

func tfApply(config Config) *exec.Cmd {
	args := []string{
		"apply",
	}
	for _, v := range config.Targets {
		args = append(args, "--target", fmt.Sprintf("%s", v))
	}
	if config.Parallelism > 0 {
		args = append(args, fmt.Sprintf("-parallelism=%d", config.Parallelism))
	}
	if config.InitOptions.Lock != nil {
		args = append(args, fmt.Sprintf("-lock=%t", *config.InitOptions.Lock))
	}
	if config.InitOptions.LockTimeout != "" {
		args = append(args, fmt.Sprintf("-lock-timeout=%s", config.InitOptions.LockTimeout))
	}
	args = append(args, getTfoutPath())

	return exec.Command(
		"terraform",
		args...,
	)
}

func tfDestroy(config Config) *exec.Cmd {
	args := []string{
		"destroy",
	}
	for _, v := range config.Targets {
		args = append(args, fmt.Sprintf("-target=%s", v))
	}
	args = append(args, varFiles(config.VarFiles)...)
	args = append(args, vars(config.Vars)...)
	if config.Parallelism > 0 {
		args = append(args, fmt.Sprintf("-parallelism=%d", config.Parallelism))
	}
	if config.InitOptions.Lock != nil {
		args = append(args, fmt.Sprintf("-lock=%t", *config.InitOptions.Lock))
	}
	if config.InitOptions.LockTimeout != "" {
		args = append(args, fmt.Sprintf("-lock-timeout=%s", config.InitOptions.LockTimeout))
	}
	args = append(args, "-force")
	return exec.Command(
		"terraform",
		args...,
	)
}

func tfPlan(config Config, destroy bool) *exec.Cmd {
	args := []string{
		"plan",
	}

	if destroy {
		args = append(args, "-destroy")
	} else {
		args = append(args, fmt.Sprintf("-out=%s", getTfoutPath()))
	}

	for _, v := range config.Targets {
		args = append(args, "--target", fmt.Sprintf("%s", v))
	}
	args = append(args, varFiles(config.VarFiles)...)
	args = append(args, vars(config.Vars)...)
	if config.Parallelism > 0 {
		args = append(args, fmt.Sprintf("-parallelism=%d", config.Parallelism))
	}
	if config.InitOptions.Lock != nil {
		args = append(args, fmt.Sprintf("-lock=%t", *config.InitOptions.Lock))
	}
	if config.InitOptions.LockTimeout != "" {
		args = append(args, fmt.Sprintf("-lock-timeout=%s", config.InitOptions.LockTimeout))
	}
	return exec.Command(
		"terraform",
		args...,
	)
}

func tfValidate(config Config) *exec.Cmd {
	args := []string{
		"validate",
	}
	for _, v := range config.VarFiles {
		args = append(args, fmt.Sprintf("-var-file=%s", v))
	}
	for k, v := range config.Vars {
		args = append(args, "-var", fmt.Sprintf("%s=%s", k, v))
	}
	return exec.Command(
		"terraform",
		args...,
	)
}

func tfFmt(config Config) *exec.Cmd {
	args := []string{
		"fmt",
	}
	if config.FmtOptions.List != nil {
		args = append(args, fmt.Sprintf("-list=%t", *config.FmtOptions.List))
	}
	if config.FmtOptions.Write != nil {
		args = append(args, fmt.Sprintf("-write=%t", *config.FmtOptions.Write))
	}
	if config.FmtOptions.Diff != nil {
		args = append(args, fmt.Sprintf("-diff=%t", *config.FmtOptions.Diff))
	}
	if config.FmtOptions.Check != nil {
		args = append(args, fmt.Sprintf("-check=%t", *config.FmtOptions.Check))
	}
	return exec.Command(
		"terraform",
		args...,
	)
}

func getTfoutPath() string {
	terraformDataDir := os.Getenv("TF_DATA_DIR")
	if terraformDataDir == ".terraform" || terraformDataDir == "" {
		return "plan.tfout"
	} else {
		return fmt.Sprintf("%s.plan.tfout", terraformDataDir)
	}
}

func vars(vs map[string]string) []string {
	var args []string
	for k, v := range vs {
		args = append(args, "-var", fmt.Sprintf("%s=%s", k, v))
	}
	return args
}

func varFiles(vfs []string) []string {
	var args []string
	for _, v := range vfs {
		args = append(args, fmt.Sprintf("-var-file=%s", v))
	}
	return args
}

// helper function to write a netrc file.
// The following code comes from the official Git plugin for Drone:
// https://github.com/drone-plugins/drone-git/blob/8386effd2fe8c8695cf979427f8e1762bd805192/utils.go#L43-L68
func writeNetrc(machine, login, password string) error {
	if machine == "" {
		return nil
	}
	out := fmt.Sprintf(
		netrcFile,
		machine,
		login,
		password,
	)

	home := "/root"
	u, err := user.Current()
	if err == nil {
		home = u.HomeDir
	}
	path := filepath.Join(home, ".netrc")
	return ioutil.WriteFile(path, []byte(out), 0600)
}

const netrcFile = `
machine %s
login %s
password %s
`
