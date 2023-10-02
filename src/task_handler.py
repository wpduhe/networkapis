from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import Future
from uuid import uuid4
from datetime import datetime


class Task:
    future = Future()
    func = None
    fetch_uri: str

    def __init__(self, static_id: str=None):
        self.creation_time = datetime.now()

        if static_id:
            self.ident = static_id
        else:
            self.ident = uuid4()

        self.fetch_uri = f'/apis/get_task_status/{self.ident}'


class TaskHandler:
    executor = ThreadPoolExecutor(max_workers=2)
    task_collection = []

    def __init__(self, name: str=None):
        self.name = name

    def submit_task(self, func=None, static_id: str=None, *args, **kwargs):
        task = Task(static_id=static_id)
        task.future = self.executor.submit(func, *args, **kwargs)
        task.func = func
        self.task_collection.append(task)
        return task.ident

    def get_task(self, ident: str):
        try:
            task = next(task for task in self.task_collection if str(task.ident) == ident)
        except StopIteration:
            return 404, {'messsage': 'Task ID not found', 'detail': 'Task ID was either already retrieved or '
                                                                    'never existed'}

        if task.future.done():
            return self.task_collection[self.task_collection.index(task)]
        else:
            return task

    def clean_up(self):
        current_time = datetime.now()

        for task in self.task_collection[:]:
            if (current_time - task.creation_time).total_seconds() > 900:
                self.task_collection.remove(task)

    def job_handler_thread(self, func=None):
        self.executor.submit(func)
