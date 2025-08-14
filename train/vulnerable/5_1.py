
import asyncio

async def task():
    sensitive_data = "Sensitive Information"
    await asyncio.sleep(1)
    return sensitive_data

async def main():
    task_obj = asyncio.create_task(task())

    original_task = asyncio.current_task()
    asyncio._swap_current_task(task_obj)

    try:
        result = await task_obj
        print(f"Task result: {result}")
    finally:
        asyncio._swap_current_task(original_task)

asyncio.run(main())
