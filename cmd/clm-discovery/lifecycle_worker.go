package main

import (
	"context"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/lifecyclejobs"
)

// aapLifecycleRenewer adapts aap.Client to the lifecycle worker Renewer interface.
type aapLifecycleRenewer struct {
	client       *aap.Client
	templateName string
	workflow     bool
}

func (a *aapLifecycleRenewer) Renew(ctx context.Context, extraVars map[string]any) (int, bool, error) {
	var (
		res aap.LaunchResult
		err error
	)
	if a.workflow {
		id, ferr := a.client.FindWorkflowJobTemplate(ctx, a.templateName)
		if ferr != nil {
			return 0, false, ferr
		}
		res, err = a.client.LaunchWorkflowJobTemplate(ctx, id, extraVars)
	} else {
		id, ferr := a.client.FindJobTemplate(ctx, a.templateName)
		if ferr != nil {
			return 0, false, ferr
		}
		res, err = a.client.LaunchJobTemplate(ctx, id, extraVars)
	}
	if err != nil {
		return 0, false, err
	}
	return res.JobID, res.Workflow, nil
}

type aapLifecyclePoller struct {
	client *aap.Client
}

func (p *aapLifecyclePoller) WaitForJob(ctx context.Context, jobID int, workflow bool, interval time.Duration) (aap.Status, error) {
	return p.client.WaitForJob(ctx, aap.LaunchResult{JobID: jobID, Workflow: workflow}, interval)
}

func newLifecycleWorkerDeps(client *aap.Client, template string, workflow bool) (lifecyclejobs.Renewer, lifecyclejobs.AAPPoller) {
	if client == nil {
		return nil, nil
	}
	return &aapLifecycleRenewer{client: client, templateName: template, workflow: workflow},
		&aapLifecyclePoller{client: client}
}
