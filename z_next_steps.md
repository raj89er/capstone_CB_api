Make an 'index.html' that will be the display for the API documentation, accessed by the route '/' in the following format:
```
<!-- Get Recipes -->
<div class="col-12">
    <div class="card mb-3">
        <div class="card-header">
            <span class="badge text-bg-success">GET</span> /recipes
        </div>
        <ul class="list-group list-group-flush">
            <li class="list-group-item">Authentication: <code>None</code></li>
            <li class="list-group-item">Example Payload: <code>N/A</code></li>
        </ul>
    </div>
</div>

<!-- Add Recipe -->
<div class="col-12">
    <div class="card mb-3">
        <div class="card-header">
            <span class="badge text-bg-warning">POST</span> /recipes
        </div>
        <ul class="list-group list-group-flush">
            <li class="list-group-item">Authentication: <code>Token Authentication</code></li>
            <li class="list-group-item">Example Payload: <code>{ "title": "Example Dish", "ingredients": [{ "name": "Salt", "quantity": "1", "units": "tsp" }], "directions": [{ "step": "1", "instruction": "Add salt." }] }</code></li>
        </ul>
    </div>
</div>
```
