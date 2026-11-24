package tools

import (
	"fmt"
	"io"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/tools/todo"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var todoCmd = &cobra.Command{
	Use:   "todo",
	Short: "Manage your todo list",
	Long:  "Add, list, complete, and mark todo items as incomplete",
}

var todoAddCmd = &cobra.Command{
	Use:   "add [task]",
	Short: "Add a new todo item",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		task := strings.Join(args, " ")
		if strings.TrimSpace(task) == "" {
			return fmt.Errorf("task must not be empty")
		}
		if err := todo.Add(task); err != nil {
			return fmt.Errorf("adding task: %w", err)
		}
		return output.Emit(map[string]any{"action": "added", "description": task}, func(io.Writer) { fmt.Fprintf(output.Std, "Added task: %s\n", task) })
	},
}

var todoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all todo items",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		tasks, err := todo.List()
		if err != nil {
			return fmt.Errorf("listing tasks: %w", err)
		}

		if tasks == nil {
			tasks = []todo.Task{}
		}
		return output.Emit(map[string]any{"tasks": tasks}, func(io.Writer) {
			if len(tasks) == 0 {
				fmt.Fprintln(output.Std, "No tasks found!")
				return
			}

			fmt.Fprintln(output.Std, "Todo Items:")
			for _, task := range tasks {
				status := "[ ]"
				if task.Completed {
					status = "[x]"
				}
				fmt.Fprintf(output.Std, "%d. %s %s\n", task.ID, status, task.Description)
			}
		})
	},
}

var todoCompleteCmd = &cobra.Command{
	Use:   "complete [id]",
	Short: "Mark a todo item as complete",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		if err := todo.Complete(id); err != nil {
			return fmt.Errorf("completing task: %w", err)
		}
		return output.Emit(map[string]any{"action": "completed", "id": id}, func(io.Writer) { fmt.Fprintf(output.Std, "Completed task: %s\n", id) })
	},
}

var todoIncompleteCmd = &cobra.Command{
	Use:   "incomplete [id]",
	Short: "Mark a todo item as incomplete",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		if err := todo.Incomplete(id); err != nil {
			return fmt.Errorf("marking task as incomplete: %w", err)
		}
		return output.Emit(map[string]any{"action": "incomplete", "id": id}, func(io.Writer) { fmt.Fprintf(output.Std, "Marked task as incomplete: %s\n", id) })
	},
}

func init() {
	cmd.RootCmd.AddCommand(todoCmd)
	todoCmd.AddCommand(todoAddCmd)
	todoCmd.AddCommand(todoListCmd)
	todoCmd.AddCommand(todoCompleteCmd)
	todoCmd.AddCommand(todoIncompleteCmd)
}
