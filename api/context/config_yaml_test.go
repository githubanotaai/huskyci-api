package context_test

import (
	. "github.com/githubanotaai/huskyci-api/api/context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("config.yaml", func() {
	Describe("wizcli_vulns", func() {
		It("always performs a full clone instead of delta sparse checkout", func() {
			caller := &ExternalCalls{}
			Expect(caller.SetConfigFile("config", "..")).To(Succeed())

			cmd := caller.GetStringFromConfigFile("wizcli_vulns.cmd")
			Expect(cmd).To(ContainSubstring(`git clone -b "%GIT_BRANCH%" --single-branch --depth 1 "%GIT_REPO%" code`))
			Expect(cmd).NotTo(ContainSubstring("HUSKYCI_DELTA_SCAN"))
			Expect(cmd).NotTo(ContainSubstring("sparse-checkout"))
			Expect(cmd).NotTo(ContainSubstring("%CHANGED_FILES%"))
		})
	})
})
