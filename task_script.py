# task_script.py
import sys
import time

def main(task_id):
    print(f"🚀 Task {task_id} started")
    time.sleep(2)
    print(f"✅ Task {task_id} finished")

if __name__ == "__main__":
    main(sys.argv[1])