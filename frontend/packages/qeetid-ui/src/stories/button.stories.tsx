import type { Meta, StoryObj } from "@storybook/react";

import { Button } from "../components/ui/button";

// Sample story — copy this file when adding coverage for a new
// primitive. The argTypes block doubles as a usage cheat-sheet.
const meta: Meta<typeof Button> = {
  title: "Primitives/Button",
  component: Button,
  parameters: {
    layout: "centered",
  },
  argTypes: {
    variant: {
      control: "select",
      options: ["default", "destructive", "outline", "secondary", "ghost", "link"],
    },
    size: {
      control: "select",
      options: ["default", "sm", "lg", "icon"],
    },
    disabled: { control: "boolean" },
  },
  tags: ["autodocs"],
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Default: Story = {
  args: {
    children: "Continue",
  },
};

export const Destructive: Story = {
  args: {
    variant: "destructive",
    children: "Delete user",
  },
};

export const Outline: Story = {
  args: {
    variant: "outline",
    children: "Cancel",
  },
};

export const Loading: Story = {
  args: {
    children: "Working…",
    disabled: true,
  },
};
