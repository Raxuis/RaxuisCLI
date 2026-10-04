package tools

import (
	"fmt"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/tools/todo"

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
		if err := todo.Add(task); err != nil {
			return fmt.Errorf("adding task: %w", err)
		}
		fmt.Printf("Added task: %s\n", task)
		return nil
	},
}

var todoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all todo items",
	RunE: func(cmd *cobra.Command, args []string) error {
		tasks, err := todo.List()
		if err != nil {
			return fmt.Errorf("listing tasks: %w", err)
		}

		if len(tasks) == 0 {
			fmt.Println("No tasks found!")
			return nil
		}

		fmt.Println("Todo Items:")
		for _, task := range tasks {
			status := "[ ]"
			if task.Completed {
				status = "[x]"
			}
			fmt.Printf("%d. %s %s\n", task.ID, status, task.Description)
		}
		return nil
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
		fmt.Printf("Completed task: %s\n", id)
		return nil
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
		fmt.Printf("Marked task as incomplete: %s\n", id)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(todoCmd)
	todoCmd.AddCommand(todoAddCmd)
	todoCmd.AddCommand(todoListCmd)
	todoCmd.AddCommand(todoCompleteCmd)
	todoCmd.AddCommand(todoIncompleteCmd)
}
