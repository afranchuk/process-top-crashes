import data from "./data.json" with { type: "json" }

export const handler = async (event, context) => {
    const parts = event.path.split("/");
    const index = parts[parts.length - 1];
    return {
        statusCode: 200,
        body: JSON.stringify(data[index]),
        headers: {
            'content-type': 'application/json'
        }
    };
};
