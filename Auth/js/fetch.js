async function authFetchJSON(url, request, bodyToken, method="POST"){
    return fetch(url, {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Body-Token': bodyToken,
        },
        body: JSON.stringify(request),
      }).then(async (response)=>{
        
        return response.json();
        
      });
}