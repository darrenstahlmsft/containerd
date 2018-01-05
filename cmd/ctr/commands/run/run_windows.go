package run

import (
	gocontext "context"

	"github.com/containerd/console"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func withTTY(terminal bool) oci.SpecOpts {
	if !terminal {
		return func(ctx gocontext.Context, client oci.Client, c *containers.Container, s *specs.Spec) error {
			s.Process.Terminal = false
			return nil
		}
	}

	con := console.Current()
	size, err := con.Size()
	if err != nil {
		logrus.WithError(err).Error("console size")
	}
	return oci.WithTTY(int(size.Width), int(size.Height))
}

func newContainer(ctx gocontext.Context, client *containerd.Client, context *cli.Context) (containerd.Container, error) {
	var (
		ref  = context.Args().First()
		id   = context.Args().Get(1)
		args = context.Args()[2:]
	)

	image, err := client.GetImage(ctx, ref)
	if err != nil {
		return nil, err
	}

	var (
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
	)
	opts = append(opts, oci.WithImageConfig(image))
	opts = append(opts, withEnv(context), withMounts(context))
	if len(args) > 0 {
		opts = append(opts, oci.WithProcessArgs(args...))
	}
	if cwd := context.String("cwd"); cwd != "" {
		opts = append(opts, oci.WithProcessCwd(cwd))
	}
	opts = append(opts, withTTY(context.Bool("tty")))

	cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(context.StringSlice("label"))))
	cOpts = append(cOpts, containerd.WithImage(image))
	cOpts = append(cOpts, containerd.WithSnapshotter(context.String("snapshotter")))
	cOpts = append(cOpts, containerd.WithNewSnapshot(id, image))
	cOpts = append(cOpts, containerd.WithRuntime(context.String("runtime"), nil))

	cOpts = append([]containerd.NewContainerOpts{containerd.WithNewSpec(opts...)}, cOpts...)
	return client.NewContainer(ctx, id, cOpts...)
}
