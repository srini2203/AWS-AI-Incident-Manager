
import boto3

client = boto3.client(
    "bedrock-runtime",
    region_name="ap-south-1"
)

response = client.converse(
    modelId="apac.amazon.nova-micro-v1:0",
    messages=[
        {
            "role": "user",
            "content": [
                {
                    "text": "You are a cloud operations assistant. "
                    "Explain in two sentences what an EC2 high CPU alarm means."
                }
            ]
        }
    ],
    inferenceConfig={
        "maxTokens": 200,
        "temperature": 0.2
    }
)

print("\n===== BEDROCK RESPONSE =====")
print(response["output"]["message"]["content"][0]["text"])

print("\nTokens used:", response["usage"]["totalTokens"])
