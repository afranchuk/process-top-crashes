import data from "./data.json" with { type: "json" }

export const handler = async (event, context) => {
    const parts = event.path.split("/");
    const index = parts[parts.length - 1];
    return {
        statusCode: 200,
        body: data[index],
        isBase64Encoded: true,
        headers: {
            'content-type': 'application/json',
            'content-encoding': 'gzip'
        }
    };
};
