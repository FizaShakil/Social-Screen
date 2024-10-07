class ApiResponse {
    constructor(statusCode, data, message = "success"){
        this.statusCode = statusCode
        this.data = data
        this.message = message
        this.success = statusCode < 400  //we put it less than 400 because response codes are less than 400
    }
}

export {ApiResponse}