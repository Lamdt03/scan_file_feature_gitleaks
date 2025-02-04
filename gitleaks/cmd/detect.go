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
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "detect secrets in code",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	initConfig()
	var (
		findings []report.Finding
		err      error
	)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	// grab source
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
			detector := Detector(cmd, cfg, dst)

			// set exit code
			exitCode, err := cmd.Flags().GetInt("exit-code")
			if err != nil {
				log.Fatal().Err(err).Msg("could not get exit code")
			}

			// determine what type of scan:
			// - git: scan the history of the repo
			// - no-git: scan files by treating the repo as a plain directory
			noGit, err := cmd.Flags().GetBool("no-git")
			if err != nil {
				log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
			}
			fromPipe, err := cmd.Flags().GetBool("pipe")
			if err != nil {
				log.Fatal().Err(err)
			}

			// start the detector scan
			if noGit {
				paths, err := sources.DirectoryTargets(dst, detector.Sema, detector.FollowSymlinks)
				if err != nil {
					log.Fatal().Err(err)
				}
				findings, err = detector.DetectFiles(paths)
				if err != nil {
					// don't exit on error, just log it
					log.Error().Err(err).Msg("")
				}
			} else if fromPipe {
				findings, err = detector.DetectReader(os.Stdin, 10)
				if err != nil {
					// log fatal to exit, no need to continue since a report
					// will not be generated when scanning from a pipe...for now
					log.Fatal().Err(err).Msg("")
				}
			} else {
				var logOpts string
				logOpts, err = cmd.Flags().GetString("log-opts")
				if err != nil {
					log.Fatal().Err(err).Msg("")
				}
				gitCmd, err := sources.NewGitLogCmd(dst, logOpts)
				if err != nil {
					log.Fatal().Err(err).Msg("")
				}
				findings, err = detector.DetectGit(gitCmd)
				if err != nil {
					// don't exit on error, just log it
					log.Error().Err(err).Msg("")
				}
			}
			reportPath := "secretReport/" + repo + ".txt"
			findingSummaryAndExit2(findings, cmd, cfg, exitCode, start, err, reportPath)
		}

	} else {

		detector := Detector(cmd, cfg, source)

		// set exit code
		exitCode, err := cmd.Flags().GetInt("exit-code")
		if err != nil {
			log.Fatal().Err(err).Msg("could not get exit code")
		}

		// determine what type of scan:
		// - git: scan the history of the repo
		// - no-git: scan files by treating the repo as a plain directory
		noGit, err := cmd.Flags().GetBool("no-git")
		if err != nil {
			log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
		}
		fromPipe, err := cmd.Flags().GetBool("pipe")
		if err != nil {
			log.Fatal().Err(err)
		}

		// start the detector scan
		if noGit {
			paths, err := sources.DirectoryTargets(source, detector.Sema, detector.FollowSymlinks)
			if err != nil {
				log.Fatal().Err(err)
			}
			findings, err = detector.DetectFiles(paths)
			if err != nil {
				// don't exit on error, just log it
				log.Error().Err(err).Msg("")
			}
		} else if fromPipe {
			findings, err = detector.DetectReader(os.Stdin, 10)
			if err != nil {
				// log fatal to exit, no need to continue since a report
				// will not be generated when scanning from a pipe...for now
				log.Fatal().Err(err).Msg("")
			}
		} else {
			var logOpts string
			logOpts, err = cmd.Flags().GetString("log-opts")
			if err != nil {
				log.Fatal().Err(err).Msg("")
			}
			gitCmd, err := sources.NewGitLogCmd(source, logOpts)
			if err != nil {
				log.Fatal().Err(err).Msg("")
			}
			findings, err = detector.DetectGit(gitCmd)
			if err != nil {
				// don't exit on error, just log it
				log.Error().Err(err).Msg("")
			}
		}

		findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
	}
}
