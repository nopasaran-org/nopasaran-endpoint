import asyncio
import logging
from tasks_publisher import read_results

async def periodic_result_reader(channel, interval=5):
    while True:
        try:
            results = read_results()
            if results:
                await channel.other.signal_task_done(results=results)
                logging.info("Results sent to the coordinator")
        except FileNotFoundError:
            logging.info(f"No result file found, retrying in {interval} seconds.")
        except Exception as e:
            logging.error(f"Error reading results: {e}")
        await asyncio.sleep(interval)