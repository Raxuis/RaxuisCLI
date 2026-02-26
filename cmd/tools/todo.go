package cmd

import (
	"fmt"
	"raxuiscli/internal/tools/todo"

	"github.com/spf13/cobra"
)

var todoCmd = &cobra.Command{
	Use:   "todo",
	Short: "Manage your todo list",
	Long:  "Add, list, complete, and delete todo items",
}

var todoAddCmd = &cobra.Command{
	Use:   "add [task]",
	Short: "Add a new todo item",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		task := args[0]
		if err := todo.Add(task); err != nil {
			fmt.Printf("Error adding task: %v\n", err)
			return
		}
		fmt.Printf("Added task: %s\n", task)
	},
}

var todoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all todo items",
	Run: func(cmd *cobra.Command, args []string) {
		tasks, err := todo.List()
		if err != nil {
			fmt.Printf("Error listing tasks: %v\n", err)
			return
		}

		if len(tasks) == 0 {
			fmt.Println("No tasks found!")
			return
		}

		fmt.Println("Todo Items:")
		for i, task := range tasks {
			status := "[ ]"
			if task.Completed {
				status = "[x]"
			}
			fmt.Printf("%d. %s %s\n", i+1, status, task.Description)
		}
	},
}

var todoCompleteCmd = &cobra.Command{
	Use:   "complete [id]",
	Short: "Mark a todo item as complete",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if err := todo.Complete(id); err != nil {
			fmt.Printf("Error completing task: %v\n", err)
			return
		}
		fmt.Printf("Completed task: %s\n", id)
	},
}

var todoIncompleteCmd = &cobra.Command{
	Use:   "incomplete [id]",
	Short: "Mark a todo item as incomplete",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if err := todo.Incomplete(id); err != nil {
			fmt.Printf("Error marking task as incomplete: %v\n", err)
			return
		}
		fmt.Printf("Marked task as incomplete: %s\n", id)
	},
}

func init() {
	rootCmd.AddCommand(todoCmd)
	todoCmd.AddCommand(todoAddCmd)
	todoCmd.AddCommand(todoListCmd)
	todoCmd.AddCommand(todoCompleteCmd)
	todoCmd.AddCommand(todoIncompleteCmd)
}
