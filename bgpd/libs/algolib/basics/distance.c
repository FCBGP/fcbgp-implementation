/*************************************************************************
 * File Name:    distance.c
 * Author:       basilguo@163.com
 * Created Time: 2022-03-26 04:45:02
 * Description:
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(void)
{
    double x1, x2, y1, y2;
    double distance = 0.0;

    scanf("%lf %lf %lf %lf",
            &x1, &y1, &x2, &y2);

    printf("%lf %lf\n", pow(x1-x2, 2),
            pow(y1-y2, 2));
    distance = sqrt(pow(x1-x2, 2) +
            pow(y1-y2, 2));

    printf("%.3lf\n", distance);

    return 0;
}
