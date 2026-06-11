import os
import traceback
from dotenv import load_dotenv
from openai import OpenAI

def test_openai():
    # Load .env file
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    print(f"API Key starting with: {api_key[:12]}..." if api_key else "No API Key found!")
    print(f"Model configured: {model}")
    
    if not api_key:
        raise Exception("No API Key found!")
        
    client = OpenAI(api_key=api_key)
    try:
        print("Sending test request to OpenAI...")
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Test"},
                {"role": "user", "content": "Hello! Say test."}
            ],
            max_tokens=10
        )
        print("Success!")
        print("Response:", response.choices[0].message.content)
    except Exception as e:
        print("OpenAI call failed!")
        print("Error type:", type(e).__name__)
        print("Error details:", str(e))
        traceback.print_exc()
        
    raise Exception("Force error to see stdout")

if __name__ == '__main__':
    test_openai()
