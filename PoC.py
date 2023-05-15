import asyncio
import aiohttp

urls = []
for id in range(1,300000):
    urls.append(f"https://hackerone.com/reports/{id}.json")
concurrent_requests = 100

async def send_request(session, url, semaphore):
    async with semaphore:
        async with session.get(url) as response:
            await response.text()
            return response.status

async def main():
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(concurrent_requests)
        tasks = []
        count = 0
        for url in urls:
            task = asyncio.ensure_future(send_request(session, url, semaphore))
            tasks.append(task)
        responses = await asyncio.gather(*tasks)
        for i, response in enumerate(responses):
            if response == 200:
                count = count + 1
        print(f"After running got {count} 200 responses")

loop = asyncio.get_event_loop()
loop.run_until_complete(main())