from celery import Celery

celery = Celery('tasks', broker='redis://localhost:6379/0')

@celery.task
def my_task():
    print('Hello, world!')