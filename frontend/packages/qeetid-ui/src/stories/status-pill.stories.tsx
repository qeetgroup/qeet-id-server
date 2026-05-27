import type { Meta, StoryObj } from "@storybook/react";

import { StatusPill } from "../components/ui/status-pill";

const meta: Meta<typeof StatusPill> = {
  title: "Primitives/StatusPill",
  component: StatusPill,
  parameters: { layout: "centered" },
  argTypes: {
    kind: {
      control: "select",
      options: ["success", "warning", "danger", "info", "neutral", "muted"],
    },
    dot: { control: "boolean" },
  },
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof StatusPill>;

export const Success: Story = { args: { kind: "success", children: "Active" } };
export const Warning: Story = { args: { kind: "warning", children: "Pending" } };
export const Danger: Story = { args: { kind: "danger", children: "Revoked" } };
export const Info: Story = { args: { kind: "info", children: "Draft" } };

export const FromStatusString: Story = {
  args: { status: "expired" },
  parameters: {
    docs: {
      description: {
        story:
          "Passing a `status` string instead of `kind`+`children` resolves both from the curated lookup table — case-insensitive.",
      },
    },
  },
};
