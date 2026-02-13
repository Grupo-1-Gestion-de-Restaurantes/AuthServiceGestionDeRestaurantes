namespace AuthServiceGestionDeRestaurantes.Application.Exceptions;

public class BusinessException : Exception
{
    public string ErrorCode { get; }
    
    public BusinessException(string errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }

    public BusinessException(string errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}