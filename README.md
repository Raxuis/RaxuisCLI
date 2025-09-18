# RaxuisCLI

A collection of [Raxuis](https://github.com/Raxuis) most used tools.

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/Raxuis/RaxuisCLI.git
cd raxuicli
````

Build the binary:

```bash
go build -o raxuicli
```

Run it locally:

```bash
./raxuicli --name Alice
```

Or install it globally:

```bash
go install .
```

Make sure `$GOPATH/bin` (usually `$HOME/go/bin`) is in your PATH:

```bash
export PATH=$PATH:$HOME/go/bin
```

Now you can run the CLI from anywhere:

```bash
raxuicli --name Alice
```

---

## ⚡ Usage

```bash
raxuicli --help
```

Output:

```
A simple greeting CLI

Usage:
  raxuicli [flags]

Flags:
  -h, --help        help for raxuicli
  -n, --name string Your name
```

Examples:

```bash
raxuicli
# Output: Hello, World!

raxuicli --name Alice
# Output: Hello, Alice!
```

---

## 🛠 Development

* Install dependencies:

```bash
go mod tidy
```

* Run without building:

```bash
go run main.go --name Bob
```

---