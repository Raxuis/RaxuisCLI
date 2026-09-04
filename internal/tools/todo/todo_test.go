package todo

import "testing"

// withTempDataDir points the package at a temp directory for the duration of
// the test, instead of the real user home directory, and restores it after.
func withTempDataDir(t *testing.T) {
	t.Helper()
	orig := dataDirOverride
	dataDirOverride = t.TempDir()
	t.Cleanup(func() { dataDirOverride = orig })
}

func TestAddAndList(t *testing.T) {
	withTempDataDir(t)

	if err := Add("first task"); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if err := Add("second task"); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	tasks, err := List()
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("List() returned %d tasks, want 2", len(tasks))
	}
	if tasks[0].ID != 1 || tasks[0].Description != "first task" {
		t.Errorf("tasks[0] = %+v, want ID=1 Description=%q", tasks[0], "first task")
	}
	if tasks[1].ID != 2 || tasks[1].Description != "second task" {
		t.Errorf("tasks[1] = %+v, want ID=2 Description=%q", tasks[1], "second task")
	}
	if tasks[0].Completed {
		t.Error("newly added task should not be Completed")
	}
}

func TestListEmpty(t *testing.T) {
	withTempDataDir(t)

	tasks, err := List()
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("List() on fresh data dir = %v, want empty", tasks)
	}
}

func TestCompleteAndIncomplete(t *testing.T) {
	withTempDataDir(t)

	if err := Add("toggle me"); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	if err := Complete("1"); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	tasks, _ := List()
	if !tasks[0].Completed {
		t.Error("task should be Completed after Complete(1)")
	}

	if err := Incomplete("1"); err != nil {
		t.Fatalf("Incomplete returned error: %v", err)
	}
	tasks, _ = List()
	if tasks[0].Completed {
		t.Error("task should not be Completed after Incomplete(1)")
	}
}

func TestCompleteInvalidID(t *testing.T) {
	withTempDataDir(t)
	if err := Complete("not-a-number"); err == nil {
		t.Error("Complete with a non-numeric ID should return an error")
	}
}

func TestCompleteMissingTask(t *testing.T) {
	withTempDataDir(t)
	if err := Complete("999"); err == nil {
		t.Error("Complete on a nonexistent task ID should return an error")
	}
}

func TestIncompleteInvalidID(t *testing.T) {
	withTempDataDir(t)
	if err := Incomplete("nope"); err == nil {
		t.Error("Incomplete with a non-numeric ID should return an error")
	}
}

func TestIncompleteMissingTask(t *testing.T) {
	withTempDataDir(t)
	if err := Incomplete("999"); err == nil {
		t.Error("Incomplete on a nonexistent task ID should return an error")
	}
}

func TestAddPersistsAcrossLoads(t *testing.T) {
	withTempDataDir(t)

	if err := Add("persisted"); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	taskList, err := loadTasks()
	if err != nil {
		t.Fatalf("loadTasks returned error: %v", err)
	}
	if len(taskList.Tasks) != 1 || taskList.Tasks[0].Description != "persisted" {
		t.Errorf("loadTasks() = %+v, want a single task %q", taskList.Tasks, "persisted")
	}
}

func TestIDsIncrementAfterGaps(t *testing.T) {
	withTempDataDir(t)

	Add("a")
	Add("b")
	Add("c")
	tasks, _ := List()
	if len(tasks) != 3 || tasks[2].ID != 3 {
		t.Fatalf("expected 3 tasks with the last ID=3, got %+v", tasks)
	}
}
