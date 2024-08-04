package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "protect secrets in code",
	Run:   runProtect,
}

func runProtect(cmd *cobra.Command, args []string) {
	initConfig()
	var err error

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	exitCode, _ := cmd.Flags().GetInt("exit-code")
	staged, _ := cmd.Flags().GetBool("staged")
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	if path.Ext(source) == ".csv" || path.Ext(source) == ".txt" {
		file, err := os.Open(source)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)
		fileScanner.Split(bufio.ScanLines)
		var rawRepos []string
		for fileScanner.Scan() {
			rawRepos = append(rawRepos, fileScanner.Text())
		}
		var repoList []string
		for _, rawRepo := range rawRepos {
			rawRepo = CleanRepo(rawRepo)
			if strings.Contains(rawRepo, "/") {
				repoList = append(repoList, rawRepo)
			} else {
				repos := GetOrgRepo(rawRepo)
				for _, repo := range repos {
					repoList = append(repoList, repo)
				}

			}
		}
		for _, repo := range repoList {
			CloneRepo(repo)
		}

		for _, repo := range repoList {
			fmt.Println(repo)
			dst := "gitRepo/" + repo + "/.git"
			start := time.Now()
			detector := Detector(cmd, cfg, dst)

			// start git scan
			var findings []report.Finding
			gitCmd, err := sources.NewGitDiffCmd(dst, staged)
			if err != nil {
				log.Fatal().Err(err).Msg("")
			}
			findings, err = detector.DetectGit(gitCmd)
			reportPath := "secretReport/" + repo + ".txt"
			findingSummaryAndExit2(findings, cmd, cfg, exitCode, start, err, reportPath)
		}
	} else {
		start := time.Now()
		detector := Detector(cmd, cfg, source)

		// start git scan
		var findings []report.Finding
		gitCmd, err := sources.NewGitDiffCmd(source, staged)
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
		findings, err = detector.DetectGit(gitCmd)

		findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
	}
}
