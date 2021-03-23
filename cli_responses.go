package jwtauth

import (
	_ "embed"
	"fmt"
)

//go:embed html/success.html
var successHTMLstr string

//go:embed html/test_ui.html
var testUIHTMLstr string

//go:embed html/error.html
var errorHTMLstr string

//go:embed html/formPost.html
var formPostHTMLstr string

func errorHTML(summary, detail string) string {
	return fmt.Sprintf(errorHTMLstr, summary, detail)
}

func formpostHTML(path, code, state string) string {
	return fmt.Sprintf(formPostHTMLstr, path, code, state)
}
