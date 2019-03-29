package org.apache.ranger.services.presto.client;

import io.prestosql.spi.ErrorCode;
import io.prestosql.spi.ErrorCodeSupplier;
import io.prestosql.spi.ErrorType;

import static io.prestosql.spi.ErrorType.EXTERNAL;

public enum RangerPrestoConnectErrorCode implements ErrorCodeSupplier {
  DRIVER_ERROR(0, EXTERNAL),
  SECURITY_ERROR(0, EXTERNAL);

  private final ErrorCode errorCode;

  RangerPrestoConnectErrorCode(int code, ErrorType type)
  {
    errorCode = new ErrorCode(code + 0x0900_0000, name(), type);
  }

  @Override
  public ErrorCode toErrorCode()
  {
    return errorCode;
  }
}
