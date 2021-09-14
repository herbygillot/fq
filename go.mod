module github.com/wader/fq

go 1.17

require (
	// bump: go-difflib /github.com\/pmezard\/go-difflib v(.*)/ git://github.com/pmezard/go-difflib|^1
	// bump: go-difflib command go get -d github.com/pmezard/go-difflib@v$LATEST && go mod tidy
	github.com/pmezard/go-difflib v1.0.0

	// fork of github.com/itchyny/gojq
	github.com/wader/gojq v0.12.1-0.20210914125041-9eeeec0df5fe
	// fork of github.com/chzyer/readline
	github.com/wader/readline v0.0.0-20210817095433-c868eb04b8b2

	// bump: golang/text /golang\.org\/x\/text v(.*)/ git://github.com/golang/text|^0
	// bump: golang/text command go get -d golang.org/x/text@v$LATEST && go mod tidy
	golang.org/x/text v0.3.7
)

require (
	github.com/itchyny/timefmt-go v0.1.3 // indirect
	golang.org/x/sys v0.0.0-20210831042530-f4d43177bf5e // indirect
)
