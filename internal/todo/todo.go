package todo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Task struct {
	ID          int       `json:"id"`
	Description string    `json:"description"`
	Completed   bool      `json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
}

type TaskList struct {
	Tasks []Task `json:"tasks"`
}

func getDataFile() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".raxuiscli", "todos.json")
}

func ensureDataDir() error {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".raxuiscli")
	return os.MkdirAll(dataDir, 0755)
}

func loadTasks() (*TaskList, error) {
	if err := ensureDataDir(); err != nil {
		return nil, err
	}

	dataFile := getDataFile()
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return &TaskList{Tasks: []Task{}}, nil
	}

	data, err := os.ReadFile(dataFile)
	if err != nil {
		return nil, err
	}

	var taskList TaskList
	if err := json.Unmarshal(data, &taskList); err != nil {
		return nil, err
	}

	return &taskList, nil
}

func saveTasks(taskList *TaskList) error {
	data, err := json.MarshalIndent(taskList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(getDataFile(), data, 0644)
}

func Add(description string) error {
	taskList, err := loadTasks()
	if err != nil {
		return err
	}

	maxID := 0
	for _, task := range taskList.Tasks {
		if task.ID > maxID {
			maxID = task.ID
		}
	}

	newTask := Task{
		ID:          maxID + 1,
		Description: description,
		Completed:   false,
		CreatedAt:   time.Now(),
	}

	taskList.Tasks = append(taskList.Tasks, newTask)
	return saveTasks(taskList)
}

func List() ([]Task, error) {
	taskList, err := loadTasks()
	if err != nil {
		return nil, err
	}

	return taskList.Tasks, nil
}

func Complete(idStr string) error {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid task ID: %s", idStr)
	}

	taskList, err := loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i := range taskList.Tasks {
		if taskList.Tasks[i].ID == id {
			taskList.Tasks[i].Completed = true
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %d not found", id)
	}

	return saveTasks(taskList)
}

func Incomplete(idStr string) error {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid task ID: %s", idStr)
	}

	taskList, err := loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i := range taskList.Tasks {
		if taskList.Tasks[i].ID == id {
			taskList.Tasks[i].Completed = false
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %d not found", id)
	}

	return saveTasks(taskList)
}
